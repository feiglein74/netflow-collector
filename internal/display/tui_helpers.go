package display

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// Locale-aware number formatter
var numberPrinter = message.NewPrinter(language.German)

// formatBytes formats bytes in human readable form (KB, MB, GB)
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// formatNumber formats a number with locale-aware thousand separators
func formatNumber(n int) string {
	return numberPrinter.Sprintf("%d", n)
}

// formatDecimal formats a float with locale-aware thousand separators and decimal point
func formatDecimal(n float64, decimals int) string {
	format := fmt.Sprintf("%%.%df", decimals)
	return numberPrinter.Sprintf(format, n)
}

// formatAge formats a duration as a compact age string
func formatAge(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// truncateEndpoint truncates an endpoint string while preserving the port
// e.g. "very-long-hostname.domain.com:443" -> "very-long-hostn…:443"
func truncateEndpoint(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Find the last colon (port separator)
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		// No port, just truncate normally
		return s[:maxLen-1] + "…"
	}

	port := s[lastColon:] // includes the colon, e.g. ":443"
	host := s[:lastColon]

	// Calculate how much space we have for the host
	// Need space for: truncated host + "…" + port
	hostMaxLen := maxLen - 1 - len(port) // -1 for ellipsis

	if hostMaxLen <= 3 {
		// Not enough space, just truncate the whole thing
		return s[:maxLen-1] + "…"
	}

	return host[:hostMaxLen] + "…" + port
}

// parseIP parses an IP string to net.IP
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

// isPrivateIP checks if an IP is in a private/local range
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Convert to 4-byte representation for IPv4
	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6 checks
		if len(ip) < 1 {
			return false
		}
		// ULA (Unique Local Address) fd00::/8 (fc00::/7 but only fd00::/8 is used in practice)
		if ip[0] == 0xfd {
			return true
		}
		// Link-local fe80::/10
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
		return false
	}
	// 10.0.0.0/8
	if ip4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}

// getPrivateRange returns which private range an IP belongs to
// IPv4: 1=10.x, 2=172.16-31.x, 3=192.168.x
// IPv6: 4=ULA (fd00::/8), 5=link-local (fe80::/10)
// 0=none/public
func getPrivateRange(ip net.IP) int {
	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6
		if len(ip) < 2 {
			return 0
		}
		if ip[0] == 0xfd {
			return 4 // ULA
		}
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return 5 // Link-local
		}
		return 0
	}
	if ip4[0] == 10 {
		return 1
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return 2
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return 3
	}
	return 0
}

// guessSubnetV4 derives a CIDR subnet from a set of IPv4 addresses
func guessSubnetV4(ips map[string]bool) string {
	if len(ips) == 0 {
		return ""
	}

	// Group IPs by private range
	rangeIPs := make(map[int][]net.IP)
	for ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				r := getPrivateRange(ip4)
				if r > 0 && r <= 3 { // Only IPv4 ranges
					rangeIPs[r] = append(rangeIPs[r], ip4)
				}
			}
		}
	}

	if len(rangeIPs) == 0 {
		return ""
	}

	// Find the range with most IPs
	var bestRange int
	var bestCount int
	for r, ipList := range rangeIPs {
		if len(ipList) > bestCount {
			bestCount = len(ipList)
			bestRange = r
		}
	}

	ipList := rangeIPs[bestRange]
	if len(ipList) == 1 {
		return ipList[0].String() + "/32"
	}

	// Find common prefix bits within the same range
	first := ipList[0]
	commonBits := 32

	for _, ip := range ipList[1:] {
		bits := commonPrefixBitsV4(first, ip)
		if bits < commonBits {
			commonBits = bits
		}
	}

	// Sanity check - don't go below /8 for 10.x, /12 for 172.x, /16 for 192.168.x
	minBits := 8
	if bestRange == 2 {
		minBits = 12
	} else if bestRange == 3 {
		minBits = 16
	}
	if commonBits < minBits {
		commonBits = minBits
	}

	// Create network address (zero out host bits)
	mask := net.CIDRMask(commonBits, 32)
	network := first.Mask(mask)

	return fmt.Sprintf("%s/%d", network.String(), commonBits)
}

// guessSubnetV6 derives a CIDR subnet from a set of IPv6 addresses
func guessSubnetV6(ips map[string]bool) string {
	if len(ips) == 0 {
		return ""
	}

	// Group IPs by IPv6 range (4=ULA, 5=link-local)
	rangeIPs := make(map[int][]net.IP)
	for ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() == nil { // IPv6 only
			r := getPrivateRange(ip)
			if r >= 4 { // IPv6 ranges
				rangeIPs[r] = append(rangeIPs[r], ip)
			}
		}
	}

	if len(rangeIPs) == 0 {
		return ""
	}

	// Find the range with most IPs
	var bestRange int
	var bestCount int
	for r, ipList := range rangeIPs {
		if len(ipList) > bestCount {
			bestCount = len(ipList)
			bestRange = r
		}
	}

	ipList := rangeIPs[bestRange]
	if len(ipList) == 1 {
		return ipList[0].String() + "/128"
	}

	// Find common prefix bits
	first := ipList[0]
	commonBits := 128

	for _, ip := range ipList[1:] {
		bits := commonPrefixBitsV6(first, ip)
		if bits < commonBits {
			commonBits = bits
		}
	}

	// Sanity check - don't go below /8 for ULA, /10 for link-local
	minBits := 8
	if bestRange == 5 { // link-local
		minBits = 10
	}
	if commonBits < minBits {
		commonBits = minBits
	}

	// Create network address (zero out host bits)
	mask := net.CIDRMask(commonBits, 128)
	network := first.Mask(mask)

	return fmt.Sprintf("%s/%d", network.String(), commonBits)
}

// commonPrefixBitsV4 returns the number of common prefix bits between two IPv4 addresses
func commonPrefixBitsV4(a, b net.IP) int {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return 0
	}

	bits := 0
	for i := 0; i < 4; i++ {
		xor := a4[i] ^ b4[i]
		if xor == 0 {
			bits += 8
		} else {
			// Count leading zeros in the XOR result
			for mask := byte(0x80); mask > 0 && (xor&mask) == 0; mask >>= 1 {
				bits++
			}
			break
		}
	}
	return bits
}

// commonPrefixBitsV6 returns the number of common prefix bits between two IPv6 addresses
func commonPrefixBitsV6(a, b net.IP) int {
	// Ensure we have 16-byte representation
	if len(a) != 16 || len(b) != 16 {
		return 0
	}

	bits := 0
	for i := 0; i < 16; i++ {
		xor := a[i] ^ b[i]
		if xor == 0 {
			bits += 8
		} else {
			// Count leading zeros in the XOR result
			for mask := byte(0x80); mask > 0 && (xor&mask) == 0; mask >>= 1 {
				bits++
			}
			break
		}
	}
	return bits
}

// sortIPsByRange sorts IPs by private range (10.x, 172.16.x, 192.168.x, IPv6) then numerically
func sortIPsByRange(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		ipA := net.ParseIP(ips[i])
		ipB := net.ParseIP(ips[j])
		if ipA == nil || ipB == nil {
			return ips[i] < ips[j]
		}

		// Get ranges (1=10.x, 2=172.16.x, 3=192.168.x, 4=ULA, 5=link-local)
		rangeA := getPrivateRange(ipA)
		rangeB := getPrivateRange(ipB)

		// Sort by range first
		if rangeA != rangeB {
			return rangeA < rangeB
		}

		// Within same range, sort by bytes
		ipA4 := ipA.To4()
		ipB4 := ipB.To4()

		if ipA4 != nil && ipB4 != nil {
			// IPv4: compare byte by byte
			for k := 0; k < 4; k++ {
				if ipA4[k] != ipB4[k] {
					return ipA4[k] < ipB4[k]
				}
			}
			return false
		}

		// IPv6: compare byte by byte
		if ipA4 == nil && ipB4 == nil {
			for k := 0; k < 16; k++ {
				if ipA[k] != ipB[k] {
					return ipA[k] < ipB[k]
				}
			}
			return false
		}

		// IPv4 before IPv6
		return ipA4 != nil
	})
}
