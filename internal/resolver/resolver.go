package resolver

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver handles DNS lookups with caching
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]cacheEntry
	macCache map[string]string // MAC address -> hostname correlation
	enabled  bool
	timeout  time.Duration
	maxAge   time.Duration
}

type cacheEntry struct {
	hostname  string
	timestamp time.Time
	notFound  bool
}

// New creates a new resolver
func New() *Resolver {
	return &Resolver{
		cache:    make(map[string]cacheEntry),
		macCache: make(map[string]string),
		enabled:  true,
		timeout:  500 * time.Millisecond,
		maxAge:   5 * time.Minute,
	}
}

// extractMACFromIPv6 extracts the MAC address from an EUI-64 based IPv6 address
// Returns empty string if not EUI-64 format
func extractMACFromIPv6(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	// Check for EUI-64 marker: bytes 11-12 should be FF:FE
	if ip[11] != 0xff || ip[12] != 0xfe {
		return ""
	}

	// Extract MAC from EUI-64 (flip bit 7 of first byte back)
	mac := make([]byte, 6)
	mac[0] = ip[8] ^ 0x02 // Flip the Universal/Local bit back
	mac[1] = ip[9]
	mac[2] = ip[10]
	// Skip FF:FE (bytes 11-12)
	mac[3] = ip[13]
	mac[4] = ip[14]
	mac[5] = ip[15]

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// isPrivateIPv6 checks if an IPv6 address is private/internal
func isPrivateIPv6(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}

	// Link-local: fe80::/10
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}

	// ULA (Unique Local Address): fc00::/7 (fc00::/8 and fd00::/8)
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}

	return false
}

// SetEnabled enables or disables DNS resolution
func (r *Resolver) SetEnabled(enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = enabled
}

// IsEnabled returns whether DNS resolution is enabled
func (r *Resolver) IsEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled
}

// Resolve returns the hostname for an IP address
// Returns the IP string if lookup fails or is disabled
func (r *Resolver) Resolve(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ipStr := ip.String()

	r.mu.RLock()
	enabled := r.enabled
	if entry, ok := r.cache[ipStr]; ok {
		if time.Since(entry.timestamp) < r.maxAge {
			r.mu.RUnlock()
			if entry.notFound {
				return ipStr
			}
			return entry.hostname
		}
	}
	r.mu.RUnlock()

	if !enabled {
		return ipStr
	}

	// Do async lookup to not block
	go r.lookup(ipStr)

	return ipStr
}

// ResolveSync does a synchronous lookup (blocks)
func (r *Resolver) ResolveSync(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ipStr := ip.String()

	r.mu.RLock()
	if entry, ok := r.cache[ipStr]; ok {
		if time.Since(entry.timestamp) < r.maxAge {
			r.mu.RUnlock()
			if entry.notFound {
				return ipStr
			}
			return entry.hostname
		}
	}
	enabled := r.enabled
	r.mu.RUnlock()

	if !enabled {
		return ipStr
	}

	return r.lookup(ipStr)
}

// Patterns for unhelpful IPv6 reverse DNS responses
var unhelpfulPatterns = []*regexp.Regexp{
	// Generic IPv6 PTR patterns like "2001-db8-1--1.ipv6.example.com"
	regexp.MustCompile(`(?i)^[0-9a-f]{1,4}[-\.][0-9a-f]{1,4}[-\.]`),
	// Patterns containing "ipv6" with hex
	regexp.MustCompile(`(?i)ipv6.*[0-9a-f]{4}`),
	// Pure hex hostnames (like fe80000000000000...)
	regexp.MustCompile(`^[0-9a-f]{12,}\.`),
	// ip6.arpa style that leaked through
	regexp.MustCompile(`(?i)ip6\.arpa`),
}

// isUnhelpfulHostname checks if a reverse DNS result is not useful
func isUnhelpfulHostname(hostname, ipStr string) bool {
	// If hostname equals IP, not helpful
	if hostname == ipStr {
		return true
	}

	// If hostname contains the IP literally
	if strings.Contains(hostname, ipStr) {
		return true
	}

	// Check for IPv6-specific unhelpful patterns
	if strings.Contains(ipStr, ":") { // Is IPv6
		for _, pattern := range unhelpfulPatterns {
			if pattern.MatchString(hostname) {
				return true
			}
		}

		// Check if hostname is mostly hex characters (unhelpful IPv6 PTR)
		hexCount := 0
		for _, c := range hostname {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-' || c == '.' {
				hexCount++
			}
		}
		// If more than 70% is hex-like, probably not a real hostname
		if len(hostname) > 10 && float64(hexCount)/float64(len(hostname)) > 0.7 {
			return true
		}
	}

	return false
}

// reverseIPv6 creates the reverse DNS name for an IPv6 address
func reverseIPv6(ip net.IP) string {
	ip = ip.To16()
	if ip == nil {
		return ""
	}

	// Build reverse name: each nibble reversed, separated by dots, ending in ip6.arpa
	var parts []string
	for i := len(ip) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", ip[i]&0x0f))
		parts = append(parts, fmt.Sprintf("%x", ip[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa."
}

// reverseIPv4 creates the reverse DNS name for an IPv4 address
func reverseIPv4(ip net.IP) string {
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip[3], ip[2], ip[1], ip[0])
}

// lookupMDNS tries to resolve an IP address via mDNS (multicast DNS)
func (r *Resolver) lookupMDNS(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// Build reverse lookup name
	var reverseName string
	var mdnsAddr string

	if ip.To4() != nil {
		reverseName = reverseIPv4(ip)
		mdnsAddr = "224.0.0.251:5353"
	} else {
		reverseName = reverseIPv6(ip)
		mdnsAddr = "[ff02::fb]:5353"
	}

	// Create PTR query
	msg := new(dns.Msg)
	msg.SetQuestion(reverseName, dns.TypePTR)
	msg.RecursionDesired = false

	// Try both IPv4 and IPv6 mDNS addresses
	addrs := []string{mdnsAddr}
	if ip.To4() == nil {
		// For IPv6 lookups, also try IPv4 mDNS (the host might respond on either)
		addrs = append(addrs, "224.0.0.251:5353")
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 500 * time.Millisecond,
	}

	for _, addr := range addrs {
		response, _, err := client.Exchange(msg, addr)
		if err != nil {
			continue
		}

		for _, answer := range response.Answer {
			if ptr, ok := answer.(*dns.PTR); ok {
				hostname := ptr.Ptr
				// Remove trailing dot
				if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
					hostname = hostname[:len(hostname)-1]
				}
				// Remove .local suffix if present (optional)
				// hostname = strings.TrimSuffix(hostname, ".local")
				return hostname
			}
		}
	}

	return ""
}

func (r *Resolver) lookup(ipStr string) string {
	// Do regular DNS lookup first
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)

	var hostname string
	dnsWorked := false

	if err == nil && len(names) > 0 {
		// Remove trailing dot from hostname
		hostname = names[0]
		if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}

		// Check if the hostname is actually helpful
		if !isUnhelpfulHostname(hostname, ipStr) {
			dnsWorked = true
		}
	}

	// If regular DNS failed or gave unhelpful result, try mDNS
	if !dnsWorked {
		if mdnsHostname := r.lookupMDNS(ipStr); mdnsHostname != "" {
			hostname = mdnsHostname
			dnsWorked = true
		}
	}

	// For IPv6: try MAC correlation as last resort
	ip := net.ParseIP(ipStr)
	var mac string
	if ip != nil && ip.To4() == nil {
		mac = extractMACFromIPv6(ip)
		if !dnsWorked && mac != "" {
			r.mu.RLock()
			if cachedHostname, ok := r.macCache[mac]; ok {
				hostname = cachedHostname
				dnsWorked = true
			}
			r.mu.RUnlock()
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !dnsWorked {
		r.cache[ipStr] = cacheEntry{
			hostname:  ipStr,
			timestamp: time.Now(),
			notFound:  true,
		}
		return ipStr
	}

	// Store in cache
	r.cache[ipStr] = cacheEntry{
		hostname:  hostname,
		timestamp: time.Now(),
		notFound:  false,
	}

	// For IPv6 with EUI-64: also store MAC -> hostname correlation
	if mac != "" {
		r.macCache[mac] = hostname
	}

	return hostname
}

// GetCached returns cached hostname or empty string
func (r *Resolver) GetCached(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	ipStr := ip.String()

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check regular cache first
	if entry, ok := r.cache[ipStr]; ok {
		if time.Since(entry.timestamp) < r.maxAge && !entry.notFound {
			return entry.hostname, true
		}
	}

	// For IPv6: try MAC correlation
	if ip.To4() == nil {
		if mac := extractMACFromIPv6(ip); mac != "" {
			if hostname, ok := r.macCache[mac]; ok {
				return hostname, true
			}
		}
	}

	return "", false
}

// CacheSize returns the number of cached entries
func (r *Resolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// Clear clears the cache
func (r *Resolver) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]cacheEntry)
}
