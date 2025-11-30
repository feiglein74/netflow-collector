package store

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netflow-collector/internal/resolver"
	"netflow-collector/pkg/types"
)

// SortField defines the field to sort by
type SortField int

const (
	SortByTime SortField = iota
	SortByBytes
	SortByPackets
	SortBySrcIP
	SortByDstIP
	SortByProtocol
)

func (s SortField) String() string {
	switch s {
	case SortByTime:
		return "Time"
	case SortByBytes:
		return "Bytes"
	case SortByPackets:
		return "Packets"
	case SortBySrcIP:
		return "Src IP"
	case SortByDstIP:
		return "Dst IP"
	case SortByProtocol:
		return "Protocol"
	default:
		return "Unknown"
	}
}

// ExprNode represents a node in the filter expression tree
type ExprNode interface {
	Evaluate(flow *types.Flow) bool
}

// ConditionNode represents a single filter condition (leaf node)
type ConditionNode struct {
	Field     string
	Value     string
	Port      uint16
	Interface uint16
	Network   *net.IPNet // For CIDR notation like 192.168.0.0/24
	Negated   bool
}

func (c *ConditionNode) Evaluate(flow *types.Flow) bool {
	srcIP := flow.SrcAddr.String()
	dstIP := flow.DstAddr.String()

	var result bool
	switch c.Field {
	case "src", "sip", "srcip":
		if c.Network != nil {
			result = c.Network.Contains(flow.SrcAddr)
		} else {
			result = strings.Contains(srcIP, c.Value)
		}
	case "dst", "dip", "dstip":
		if c.Network != nil {
			result = c.Network.Contains(flow.DstAddr)
		} else {
			result = strings.Contains(dstIP, c.Value)
		}
	case "ip", "host":
		if c.Network != nil {
			result = c.Network.Contains(flow.SrcAddr) || c.Network.Contains(flow.DstAddr)
		} else {
			result = strings.Contains(srcIP, c.Value) || strings.Contains(dstIP, c.Value)
		}
	case "sport", "srcport":
		result = flow.SrcPort == c.Port
	case "dport", "dstport":
		result = flow.DstPort == c.Port
	case "port":
		result = flow.SrcPort == c.Port || flow.DstPort == c.Port
	case "proto", "protocol":
		result = strings.EqualFold(flow.ProtocolName(), c.Value)
	case "service", "svc":
		// Check if either port matches the service name
		srcSvc := resolver.GetServiceName(flow.SrcPort, flow.Protocol)
		dstSvc := resolver.GetServiceName(flow.DstPort, flow.Protocol)
		// Fallback to protocol name if no service found (e.g., ICMP)
		if srcSvc == "" && dstSvc == "" {
			result = strings.EqualFold(flow.ProtocolName(), c.Value)
		} else {
			result = strings.EqualFold(srcSvc, c.Value) || strings.EqualFold(dstSvc, c.Value)
		}
	case "if":
		// Match either input or output interface
		result = flow.InputIf == c.Interface || flow.OutputIf == c.Interface
	case "inif":
		result = flow.InputIf == c.Interface
	case "outif":
		result = flow.OutputIf == c.Interface
	default:
		result = true
	}

	if c.Negated {
		return !result
	}
	return result
}

// AndNode represents AND of multiple expressions
type AndNode struct {
	Children []ExprNode
}

func (a *AndNode) Evaluate(flow *types.Flow) bool {
	for _, child := range a.Children {
		if !child.Evaluate(flow) {
			return false
		}
	}
	return true
}

// OrNode represents OR of multiple expressions
type OrNode struct {
	Children []ExprNode
}

func (o *OrNode) Evaluate(flow *types.Flow) bool {
	for _, child := range o.Children {
		if child.Evaluate(flow) {
			return true
		}
	}
	return false
}

// NotNode represents negation of an expression
type NotNode struct {
	Child ExprNode
}

func (n *NotNode) Evaluate(flow *types.Flow) bool {
	return !n.Child.Evaluate(flow)
}

// Filter defines criteria for filtering flows
// Supports: src=x dst=x ip=x sport=x dport=x port=x proto=x
// Operators: && (AND), || (OR), ! (NOT), () (grouping)
type Filter struct {
	Root  ExprNode // Root of expression tree
	Raw   string   // original filter string for display
	Error string   // parse error message, empty if valid
}

// IsEmpty returns true if no filters are set
func (f *Filter) IsEmpty() bool {
	return f.Root == nil
}

// IsValid returns true if the filter has no parse errors
func (f *Filter) IsValid() bool {
	return f.Error == ""
}

// Matches returns true if the flow matches the filter
func (f *Filter) Matches(flow *types.Flow) bool {
	if f.Root == nil {
		return true
	}
	return f.Root.Evaluate(flow)
}

// ValidFields lists all valid filter field names
var ValidFields = map[string]bool{
	"src": true, "sip": true, "srcip": true,
	"dst": true, "dip": true, "dstip": true,
	"ip": true, "host": true,
	"sport": true, "srcport": true,
	"dport": true, "dstport": true,
	"port": true,
	"proto": true, "protocol": true,
	"service": true, "svc": true,
	"if": true, "inif": true, "outif": true,
}

// Token types for the filter parser
type tokenType int

const (
	tokenCondition tokenType = iota
	tokenAnd
	tokenOr
	tokenNot
	tokenLParen
	tokenRParen
	tokenEOF
	tokenError
)

type token struct {
	typ   tokenType
	value string
}

// tokenize breaks the filter string into tokens
func tokenize(s string) []token {
	var tokens []token
	s = strings.TrimSpace(s)
	i := 0

	for i < len(s) {
		// Skip whitespace
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}

		// Check for operators and parentheses
		if i+1 < len(s) && s[i:i+2] == "&&" {
			tokens = append(tokens, token{tokenAnd, "&&"})
			i += 2
			continue
		}
		if i+1 < len(s) && s[i:i+2] == "||" {
			tokens = append(tokens, token{tokenOr, "||"})
			i += 2
			continue
		}
		if s[i] == '!' {
			tokens = append(tokens, token{tokenNot, "!"})
			i++
			continue
		}
		if s[i] == '(' {
			tokens = append(tokens, token{tokenLParen, "("})
			i++
			continue
		}
		if s[i] == ')' {
			tokens = append(tokens, token{tokenRParen, ")"})
			i++
			continue
		}

		// Check for "not" keyword (case insensitive)
		if i+3 <= len(s) && strings.EqualFold(s[i:i+3], "not") {
			// Make sure it's followed by whitespace or ( to be a keyword
			if i+3 >= len(s) || s[i+3] == ' ' || s[i+3] == '\t' || s[i+3] == '(' {
				tokens = append(tokens, token{tokenNot, "not"})
				i += 3
				continue
			}
		}

		// Check for "and" keyword
		if i+3 <= len(s) && strings.EqualFold(s[i:i+3], "and") {
			if i+3 >= len(s) || s[i+3] == ' ' || s[i+3] == '\t' || s[i+3] == '(' {
				tokens = append(tokens, token{tokenAnd, "and"})
				i += 3
				continue
			}
		}

		// Check for "or" keyword
		if i+2 <= len(s) && strings.EqualFold(s[i:i+2], "or") {
			if i+2 >= len(s) || s[i+2] == ' ' || s[i+2] == '\t' || s[i+2] == '(' {
				tokens = append(tokens, token{tokenOr, "or"})
				i += 2
				continue
			}
		}

		// Read a condition (everything until space, paren, or operator)
		start := i
		for i < len(s) {
			c := s[i]
			if c == ' ' || c == '\t' || c == '(' || c == ')' {
				break
			}
			if i+1 < len(s) && (s[i:i+2] == "&&" || s[i:i+2] == "||") {
				break
			}
			i++
		}
		if i > start {
			tokens = append(tokens, token{tokenCondition, s[start:i]})
		}
	}

	tokens = append(tokens, token{tokenEOF, ""})
	return tokens
}

// parser holds the parser state
type parser struct {
	tokens  []token
	pos     int
	errors  []string
}

func (p *parser) current() token {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return token{tokenEOF, ""}
}

func (p *parser) advance() {
	if p.pos < len(p.tokens) {
		p.pos++
	}
}

// parseExpr parses an expression (handles OR - lowest precedence)
func (p *parser) parseExpr() ExprNode {
	left := p.parseAndExpr()
	if left == nil {
		return nil
	}

	var children []ExprNode
	children = append(children, left)

	for p.current().typ == tokenOr {
		p.advance()
		right := p.parseAndExpr()
		if right == nil {
			p.errors = append(p.errors, "expected expression after ||")
			break
		}
		children = append(children, right)
	}

	if len(children) == 1 {
		return children[0]
	}
	return &OrNode{Children: children}
}

// parseAndExpr parses AND expressions (space-separated or &&)
func (p *parser) parseAndExpr() ExprNode {
	left := p.parseUnaryExpr()
	if left == nil {
		return nil
	}

	var children []ExprNode
	children = append(children, left)

	for {
		// Explicit AND
		if p.current().typ == tokenAnd {
			p.advance()
			right := p.parseUnaryExpr()
			if right == nil {
				p.errors = append(p.errors, "expected expression after &&")
				break
			}
			children = append(children, right)
			continue
		}

		// Implicit AND: condition or ( or ! following directly
		cur := p.current()
		if cur.typ == tokenCondition || cur.typ == tokenLParen || cur.typ == tokenNot {
			right := p.parseUnaryExpr()
			if right == nil {
				break
			}
			children = append(children, right)
			continue
		}

		break
	}

	if len(children) == 1 {
		return children[0]
	}
	return &AndNode{Children: children}
}

// parseUnaryExpr parses NOT expressions and primary expressions
func (p *parser) parseUnaryExpr() ExprNode {
	if p.current().typ == tokenNot {
		p.advance()
		child := p.parseUnaryExpr()
		if child == nil {
			p.errors = append(p.errors, "expected expression after !")
			return nil
		}
		return &NotNode{Child: child}
	}
	return p.parsePrimaryExpr()
}

// parsePrimaryExpr parses conditions and parenthesized expressions
func (p *parser) parsePrimaryExpr() ExprNode {
	cur := p.current()

	if cur.typ == tokenLParen {
		p.advance()
		expr := p.parseExpr()
		if expr == nil {
			p.errors = append(p.errors, "expected expression after (")
			return nil
		}
		if p.current().typ != tokenRParen {
			p.errors = append(p.errors, "missing closing )")
		} else {
			p.advance()
		}
		return expr
	}

	if cur.typ == tokenCondition {
		p.advance()
		return p.parseCondition(cur.value)
	}

	return nil
}

// parseCondition parses a single field=value condition
func (p *parser) parseCondition(s string) ExprNode {
	var key, value string
	var negated bool

	// Check for != operator
	if idx := strings.Index(s, "!="); idx > 0 {
		key = strings.ToLower(s[:idx])
		value = s[idx+2:]
		negated = true
	} else {
		// Try key=value or key:value format
		idx := strings.Index(s, "=")
		if idx < 0 {
			idx = strings.Index(s, ":")
		}
		if idx <= 0 {
			p.errors = append(p.errors, s+" (invalid syntax)")
			return nil
		}
		key = strings.ToLower(s[:idx])
		value = s[idx+1:]
	}

	// Validate field name
	if !ValidFields[key] {
		p.errors = append(p.errors, s+" (unknown field)")
		return nil
	}

	// Validate value is not empty
	if value == "" {
		p.errors = append(p.errors, s+" (empty value)")
		return nil
	}

	cond := &ConditionNode{Field: key, Value: value, Negated: negated}

	// Parse CIDR notation for IP fields
	if key == "src" || key == "sip" || key == "srcip" ||
		key == "dst" || key == "dip" || key == "dstip" ||
		key == "ip" || key == "host" {
		if strings.Contains(value, "/") {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				p.errors = append(p.errors, s+" (invalid CIDR)")
				return nil
			}
			cond.Network = network
		}
	}

	// Parse port values
	if key == "sport" || key == "srcport" || key == "dport" || key == "dstport" || key == "port" {
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			p.errors = append(p.errors, s+" (invalid port)")
			return nil
		}
		cond.Port = uint16(port)
	}

	// Parse interface values
	if key == "if" || key == "inif" || key == "outif" {
		iface, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			p.errors = append(p.errors, s+" (invalid interface)")
			return nil
		}
		cond.Interface = uint16(iface)
	}

	// Validate protocol
	if key == "proto" || key == "protocol" {
		validProtos := map[string]bool{
			"tcp": true, "udp": true, "icmp": true, "gre": true,
			"esp": true, "ah": true, "icmpv6": true, "sctp": true,
		}
		if !validProtos[strings.ToLower(value)] {
			p.errors = append(p.errors, s+" (unknown protocol)")
			return nil
		}
	}

	return cond
}

// ParseFilter parses a Wireshark-like filter string with full expression support
// Examples:
//   - "src=192.168 && proto=tcp" - AND
//   - "port=80 || port=443" - OR
//   - "!proto=udp" or "not proto=udp" - NOT
//   - "src=192.168 proto=tcp" - space = implicit AND
//   - "!(src=10.0.0.1 && port=53)" - parentheses for grouping
func ParseFilter(s string) Filter {
	f := Filter{Raw: strings.TrimSpace(s)}
	s = strings.TrimSpace(s)
	if s == "" {
		return f
	}

	tokens := tokenize(s)
	p := &parser{tokens: tokens}

	f.Root = p.parseExpr()

	// Check for trailing tokens
	if p.current().typ != tokenEOF {
		p.errors = append(p.errors, "unexpected: "+p.current().value)
	}

	if len(p.errors) > 0 {
		f.Error = "invalid: " + strings.Join(p.errors, ", ")
		f.Root = nil // Don't use partial parse
	}

	return f
}

// String returns the filter as a string
func (f *Filter) String() string {
	if f.Raw != "" {
		return f.Raw
	}
	return ""
}

// Stats holds statistics about received flows
type Stats struct {
	TotalFlows      uint64
	TotalBytes      uint64
	TotalPackets    uint64
	FlowsPerSecond  float64
	BytesPerSecond  float64
	V5Flows         uint64
	V9Flows         uint64
	IPFIXFlows      uint64
	UniqueExporters int
}

// FlowStore stores flows in memory
type FlowStore struct {
	mu              sync.RWMutex
	flows           []types.Flow
	maxFlows        int
	stats           Stats
	exporters       map[string]bool
	lastStatsUpdate time.Time
	flowsInWindow   int
	bytesInWindow   uint64
}

// New creates a new flow store
func New(maxFlows int) *FlowStore {
	if maxFlows == 0 {
		maxFlows = 100000
	}

	fs := &FlowStore{
		flows:           make([]types.Flow, 0, maxFlows),
		maxFlows:        maxFlows,
		exporters:       make(map[string]bool),
		lastStatsUpdate: time.Now(),
	}

	return fs
}

// Add adds flows to the store
func (fs *FlowStore) Add(flows []types.Flow) {
	if len(flows) == 0 {
		return
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	for _, flow := range flows {
		// Update stats
		fs.stats.TotalFlows++
		fs.stats.TotalBytes += flow.Bytes
		fs.stats.TotalPackets += flow.Packets
		fs.flowsInWindow++
		fs.bytesInWindow += flow.Bytes

		switch flow.Version {
		case types.NetFlowV5:
			fs.stats.V5Flows++
		case types.NetFlowV9:
			fs.stats.V9Flows++
		case types.IPFIX:
			fs.stats.IPFIXFlows++
		}

		if flow.ExporterIP != nil {
			fs.exporters[flow.ExporterIP.String()] = true
		}

		fs.flows = append(fs.flows, flow)
	}

	// Trim if over max
	if len(fs.flows) > fs.maxFlows {
		fs.flows = fs.flows[len(fs.flows)-fs.maxFlows:]
	}

	// Update rates every second
	now := time.Now()
	elapsed := now.Sub(fs.lastStatsUpdate).Seconds()
	if elapsed >= 1.0 {
		fs.stats.FlowsPerSecond = float64(fs.flowsInWindow) / elapsed
		fs.stats.BytesPerSecond = float64(fs.bytesInWindow) / elapsed
		fs.stats.UniqueExporters = len(fs.exporters)
		fs.flowsInWindow = 0
		fs.bytesInWindow = 0
		fs.lastStatsUpdate = now
	}
}

// Query returns flows matching the filter, sorted by the specified field
func (fs *FlowStore) Query(filter *Filter, sortBy SortField, ascending bool, limit int) []types.Flow {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Filter flows
	var filtered []types.Flow
	if filter == nil || filter.IsEmpty() {
		filtered = make([]types.Flow, len(fs.flows))
		copy(filtered, fs.flows)
	} else {
		filtered = make([]types.Flow, 0)
		for i := range fs.flows {
			if filter.Matches(&fs.flows[i]) {
				filtered = append(filtered, fs.flows[i])
			}
		}
	}

	// Sort flows
	sort.Slice(filtered, func(i, j int) bool {
		var less bool
		switch sortBy {
		case SortByTime:
			less = filtered[i].ReceivedAt.Before(filtered[j].ReceivedAt)
		case SortByBytes:
			less = filtered[i].Bytes < filtered[j].Bytes
		case SortByPackets:
			less = filtered[i].Packets < filtered[j].Packets
		case SortBySrcIP:
			less = compareIPs(filtered[i].SrcAddr, filtered[j].SrcAddr) < 0
		case SortByDstIP:
			less = compareIPs(filtered[i].DstAddr, filtered[j].DstAddr) < 0
		case SortByProtocol:
			less = filtered[i].Protocol < filtered[j].Protocol
		default:
			less = filtered[i].ReceivedAt.Before(filtered[j].ReceivedAt)
		}
		if ascending {
			return less
		}
		return !less
	})

	// Limit results
	if limit > 0 && limit < len(filtered) {
		filtered = filtered[:limit]
	}

	return filtered
}

// compareIPs compares two IP addresses
func compareIPs(a, b net.IP) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	aStr := a.String()
	bStr := b.String()
	if aStr < bStr {
		return -1
	}
	if aStr > bStr {
		return 1
	}
	return 0
}

// GetRecent returns the most recent flows
func (fs *FlowStore) GetRecent(count int) []types.Flow {
	return fs.Query(nil, SortByTime, false, count)
}

// GetTopByBytes returns top flows by bytes
func (fs *FlowStore) GetTopByBytes(count int) []types.Flow {
	return fs.Query(nil, SortByBytes, false, count)
}

// GetTopByPackets returns top flows by packets
func (fs *FlowStore) GetTopByPackets(count int) []types.Flow {
	return fs.Query(nil, SortByPackets, false, count)
}

// GetStats returns current statistics
func (fs *FlowStore) GetStats() Stats {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.stats
}

// GetFlowCount returns the current number of stored flows
func (fs *FlowStore) GetFlowCount() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.flows)
}

// GetMaxFlows returns the maximum number of flows that can be stored
func (fs *FlowStore) GetMaxFlows() int {
	return fs.maxFlows
}

// GetFilteredCount returns the count of flows matching a filter
func (fs *FlowStore) GetFilteredCount(filter *Filter) int {
	if filter == nil || filter.IsEmpty() {
		return fs.GetFlowCount()
	}

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	count := 0
	for i := range fs.flows {
		if filter.Matches(&fs.flows[i]) {
			count++
		}
	}
	return count
}

// FilteredStats holds statistics for filtered flows
type FilteredStats struct {
	Count   int
	Bytes   uint64
	Packets uint64
}

// GetFilteredStats returns count, bytes, and packets for flows matching a filter
func (fs *FlowStore) GetFilteredStats(filter *Filter) FilteredStats {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var stats FilteredStats
	for i := range fs.flows {
		if filter == nil || filter.IsEmpty() || filter.Matches(&fs.flows[i]) {
			stats.Count++
			stats.Bytes += fs.flows[i].Bytes
			stats.Packets += fs.flows[i].Packets
		}
	}
	return stats
}


// Clear removes all flows
func (fs *FlowStore) Clear() {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.flows = fs.flows[:0]
}
