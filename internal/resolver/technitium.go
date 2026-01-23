package resolver

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TechnitiumClient polls DNS query logs from Technitium DNS Server
type TechnitiumClient struct {
	serverURL    string
	token        string
	appName      string
	classPath    string
	resolver     *Resolver
	client       *http.Client
	pollInterval time.Duration

	mu               sync.Mutex
	lastQuery        time.Time
	running          bool
	stopCh           chan struct{}
	lastError        error
	errorCount       int
	entriesProcessed int
	entriesInjected  int
}

// TechnitiumConfig holds configuration for the Technitium client
type TechnitiumConfig struct {
	ServerURL    string        // e.g., "http://192.168.1.1:5380"
	Token        string        // API token
	AppName      string        // DNS App name (e.g., "Query Logs (Sqlite)")
	ClassPath    string        // DNS App class path (e.g., "QueryLogsSqlite.App")
	PollInterval time.Duration // How often to poll (default: 5s)
}

// QueryLogResponse represents the API response
type QueryLogResponse struct {
	Status   string `json:"status"`
	Response struct {
		PageNumber     int            `json:"pageNumber"`
		TotalPages     int            `json:"totalPages"`
		TotalEntries   int            `json:"totalEntries"`
		Entries        []QueryLogEntry `json:"entries"`
	} `json:"response"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// QueryLogEntry represents a single DNS query log entry
type QueryLogEntry struct {
	RowNumber       int       `json:"rowNumber"`
	Timestamp       string    `json:"timestamp"`
	ClientIP        string    `json:"clientIpAddress"`
	Protocol        string    `json:"protocol"`
	ResponseType    string    `json:"responseType"`
	ResponseRTT     float64   `json:"responseRtt"`
	RCode           string    `json:"rcode"`
	QName           string    `json:"qname"`
	QType           string    `json:"qtype"`
	QClass          string    `json:"qclass"`
	Answer          string    `json:"answer"`
}

// NewTechnitiumClient creates a new Technitium DNS client
func NewTechnitiumClient(config TechnitiumConfig, resolver *Resolver) *TechnitiumClient {
	if config.PollInterval == 0 {
		config.PollInterval = 5 * time.Second
	}
	if config.AppName == "" {
		config.AppName = "Query Logs (Sqlite)"
	}
	if config.ClassPath == "" {
		config.ClassPath = "QueryLogsSqlite.App"
	}

	return &TechnitiumClient{
		serverURL:    strings.TrimSuffix(config.ServerURL, "/"),
		token:        config.Token,
		appName:      config.AppName,
		classPath:    config.ClassPath,
		resolver:     resolver,
		pollInterval: config.PollInterval,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins polling for DNS query logs
func (tc *TechnitiumClient) Start() error {
	tc.mu.Lock()
	if tc.running {
		tc.mu.Unlock()
		return fmt.Errorf("technitium client already running")
	}
	tc.running = true
	tc.lastQuery = time.Now().Add(-1 * time.Minute) // Start with last minute
	tc.mu.Unlock()

	go tc.pollLoop()
	return nil
}

// Stop stops the polling
func (tc *TechnitiumClient) Stop() {
	tc.mu.Lock()
	if tc.running {
		close(tc.stopCh)
		tc.running = false
	}
	tc.mu.Unlock()
}

// IsRunning returns whether the client is polling
func (tc *TechnitiumClient) IsRunning() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return tc.running
}

func (tc *TechnitiumClient) pollLoop() {
	ticker := time.NewTicker(tc.pollInterval)
	defer ticker.Stop()

	// Initial fetch
	tc.fetchAndProcess()

	for {
		select {
		case <-ticker.C:
			tc.fetchAndProcess()
		case <-tc.stopCh:
			return
		}
	}
}

func (tc *TechnitiumClient) fetchAndProcess() {
	tc.mu.Lock()
	start := tc.lastQuery
	tc.mu.Unlock()

	end := time.Now()
	entries, err := tc.fetchQueryLogs(start, end)
	if err != nil {
		tc.mu.Lock()
		tc.lastError = err
		tc.errorCount++
		tc.mu.Unlock()
		return
	}

	// Process entries and inject into resolver cache
	injected := 0
	for _, entry := range entries {
		if tc.processEntry(entry) {
			injected++
		}
	}

	tc.mu.Lock()
	tc.lastQuery = end
	tc.entriesProcessed += len(entries)
	tc.entriesInjected += injected
	tc.lastError = nil
	tc.mu.Unlock()
}

func (tc *TechnitiumClient) fetchQueryLogs(start, end time.Time) ([]QueryLogEntry, error) {
	params := url.Values{}
	params.Set("token", tc.token)
	params.Set("name", tc.appName)
	params.Set("classPath", tc.classPath)
	params.Set("start", start.UTC().Format(time.RFC3339))
	params.Set("end", end.UTC().Format(time.RFC3339))
	params.Set("entriesPerPage", "1000")
	params.Set("descendingOrder", "true")
	// Only get successful responses with answers
	params.Set("rcode", "NoError")

	apiURL := fmt.Sprintf("%s/api/logs/query?%s", tc.serverURL, params.Encode())

	resp, err := tc.client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response failed: %w", err)
	}

	var logResp QueryLogResponse
	if err := json.Unmarshal(body, &logResp); err != nil {
		return nil, fmt.Errorf("parsing JSON failed: %w", err)
	}

	if logResp.Status != "ok" {
		return nil, fmt.Errorf("API error: %s", logResp.ErrorMessage)
	}

	return logResp.Response.Entries, nil
}

func (tc *TechnitiumClient) processEntry(entry QueryLogEntry) bool {
	// Only process A and AAAA records (forward lookups with IP answers)
	if entry.QType != "A" && entry.QType != "AAAA" {
		return false
	}

	// Skip empty answers
	if entry.Answer == "" {
		return false
	}

	// Parse the answer to extract IPs
	// Answer format can be: "192.168.1.1" or "192.168.1.1; 192.168.1.2" or JSON
	hostname := strings.TrimSuffix(entry.QName, ".")

	// Extract IPs from answer
	ips := tc.parseAnswer(entry.Answer)

	// Inject each IP -> hostname mapping into resolver cache
	injected := false
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			tc.resolver.InjectCache(ipStr, hostname)
			injected = true
		}
	}
	return injected
}

// parseAnswer extracts IP addresses from a DNS answer string
// Technitium format: "A 17.253.15.153, A 17.253.15.133" or "AAAA 2a01:..., AAAA 2a01:..."
// May also contain CNAME entries which we skip
func (tc *TechnitiumClient) parseAnswer(answer string) []string {
	var ips []string

	// Split by comma (Technitium uses ", " as separator)
	parts := strings.Split(answer, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// Check for "A <ip>" or "AAAA <ip>" format
		if strings.HasPrefix(part, "A ") {
			// IPv4: "A 17.253.15.153"
			ipStr := strings.TrimPrefix(part, "A ")
			ipStr = strings.TrimSpace(ipStr)
			if ip := net.ParseIP(ipStr); ip != nil {
				ips = append(ips, ipStr)
			}
		} else if strings.HasPrefix(part, "AAAA ") {
			// IPv6: "AAAA 2a01:b740:..."
			ipStr := strings.TrimPrefix(part, "AAAA ")
			ipStr = strings.TrimSpace(ipStr)
			if ip := net.ParseIP(ipStr); ip != nil {
				ips = append(ips, ipStr)
			}
		}
		// Skip CNAME, MX, TXT, etc.
	}

	// Fallback: try direct IP parsing (in case format changes)
	if len(ips) == 0 {
		if ip := net.ParseIP(strings.TrimSpace(answer)); ip != nil {
			ips = append(ips, strings.TrimSpace(answer))
		}
	}

	return ips
}

// TechnitiumStats holds statistics about the Technitium client
type TechnitiumStats struct {
	LastPoll         time.Time
	IsRunning        bool
	LastError        error
	ErrorCount       int
	EntriesProcessed int
	EntriesInjected  int
}

// GetStats returns statistics about the Technitium integration
func (tc *TechnitiumClient) GetStats() TechnitiumStats {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return TechnitiumStats{
		LastPoll:         tc.lastQuery,
		IsRunning:        tc.running,
		LastError:        tc.lastError,
		ErrorCount:       tc.errorCount,
		EntriesProcessed: tc.entriesProcessed,
		EntriesInjected:  tc.entriesInjected,
	}
}
