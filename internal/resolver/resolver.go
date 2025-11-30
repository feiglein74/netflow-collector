package resolver

import (
	"context"
	"net"
	"sync"
	"time"
)

// Resolver handles DNS lookups with caching
type Resolver struct {
	mu       sync.RWMutex
	cache    map[string]cacheEntry
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
		cache:   make(map[string]cacheEntry),
		enabled: true,
		timeout: 500 * time.Millisecond,
		maxAge:  5 * time.Minute,
	}
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

func (r *Resolver) lookup(ipStr string) string {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ipStr)

	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil || len(names) == 0 {
		r.cache[ipStr] = cacheEntry{
			hostname:  ipStr,
			timestamp: time.Now(),
			notFound:  true,
		}
		return ipStr
	}

	// Remove trailing dot from hostname
	hostname := names[0]
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	r.cache[ipStr] = cacheEntry{
		hostname:  hostname,
		timestamp: time.Now(),
		notFound:  false,
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

	if entry, ok := r.cache[ipStr]; ok {
		if time.Since(entry.timestamp) < r.maxAge && !entry.notFound {
			return entry.hostname, true
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
