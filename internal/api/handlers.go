package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netflow-collector/internal/resolver"
	"netflow-collector/internal/store"
	"netflow-collector/pkg/types"
)

// Handlers hält die API-Handler und Abhängigkeiten
type Handlers struct {
	store    *store.FlowStore
	resolver *resolver.Resolver
}

// NewHandlers erstellt eine neue Handlers-Instanz
func NewHandlers(flowStore *store.FlowStore) *Handlers {
	return &Handlers{store: flowStore, resolver: nil}
}

// NewHandlersWithResolver erstellt eine neue Handlers-Instanz mit DNS-Resolver
func NewHandlersWithResolver(flowStore *store.FlowStore, res *resolver.Resolver) *Handlers {
	return &Handlers{store: flowStore, resolver: res}
}

// resolveIP gibt den Hostnamen für eine IP zurück, oder die IP selbst wenn kein Resolver verfügbar
func (h *Handlers) resolveIP(ip net.IP) string {
	if h.resolver == nil || ip == nil {
		return ip.String()
	}
	// Versuche aus dem Cache zu holen (nicht blockierend)
	if hostname, found := h.resolver.GetCached(ip); found {
		return hostname
	}
	return ip.String()
}

// parseTimeRange parst Zeitraum-Strings wie "5m", "1h", "24h"
// Gibt duration zurück, 0 = kein Filter (alle Flows)
func parseTimeRange(s string) time.Duration {
	if s == "" || s == "all" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}

// HandleSankey returns aggregated flow data for Sankey visualization
func (h *Handlers) HandleSankey(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "ip-to-ip"
	}

	filterStr := r.URL.Query().Get("filter")
	ipVersion := r.URL.Query().Get("ipVersion") // "v4", "v6", or "" (all)
	topN := 50
	if n, err := strconv.Atoi(r.URL.Query().Get("topN")); err == nil && n > 0 {
		topN = n
	}

	// Parse filter - combine with IP version filter if specified
	var filter *store.Filter
	combinedFilter := filterStr
	if ipVersion == "v4" {
		if combinedFilter != "" {
			combinedFilter = "(" + combinedFilter + ") && version=4"
		} else {
			combinedFilter = "version=4"
		}
	} else if ipVersion == "v6" {
		if combinedFilter != "" {
			combinedFilter = "(" + combinedFilter + ") && version=6"
		} else {
			combinedFilter = "version=6"
		}
	}

	if combinedFilter != "" {
		f := store.ParseFilter(combinedFilter)
		if !f.IsValid() {
			writeError(w, http.StatusBadRequest, "Invalid filter", f.Error)
			return
		}
		filter = &f
	}

	// Zeitraum-Filter parsen
	timeRangeStr := r.URL.Query().Get("timeRange")
	timeRange := parseTimeRange(timeRangeStr)
	var cutoffTime time.Time
	if timeRange > 0 {
		cutoffTime = time.Now().Add(-timeRange)
	}

	// Interface-Parameter für Firewall-Modus parsen
	var leftIF, rightIF uint16
	if l, err := strconv.ParseUint(r.URL.Query().Get("leftIF"), 10, 16); err == nil {
		leftIF = uint16(l)
	}
	if ri, err := strconv.ParseUint(r.URL.Query().Get("rightIF"), 10, 16); err == nil {
		rightIF = uint16(ri)
	}

	// Exporter-Filter parsen (kann komma-separiert sein für mehrere)
	leftExporter := r.URL.Query().Get("leftExporter")
	rightExporter := r.URL.Query().Get("rightExporter")

	var data SankeyData
	switch mode {
	case "ip-to-ip":
		data = h.aggregateIPtoIP(filter, topN, cutoffTime)
	case "ip-to-service":
		data = h.aggregateIPtoService(filter, topN, cutoffTime)
	case "firewall":
		data = h.aggregateFirewall(filter, topN, cutoffTime, leftIF, rightIF, leftExporter, rightExporter)
	default:
		writeError(w, http.StatusBadRequest, "Invalid mode", "Supported modes: ip-to-ip, ip-to-service, firewall")
		return
	}

	data.Mode = mode
	data.Generated = time.Now()
	data.Filter = filterStr

	writeJSON(w, data)
}

// aggregateIPtoIP creates Sankey data for IP-to-IP visualization
func (h *Handlers) aggregateIPtoIP(filter *store.Filter, topN int, cutoffTime time.Time) SankeyData {
	// Get flows sorted by bytes (descending)
	flows := h.store.Query(filter, store.SortByBytes, false, 0)

	// Aggregate by normalized IP pair (smaller IP first to merge bidirectional flows)
	linkMap := make(map[string]*SankeyLink)
	protoCount := make(map[string]map[string]uint64) // Track protocol bytes for each link

	for i := range flows {
		f := &flows[i]

		// Zeit-Filter anwenden
		if !cutoffTime.IsZero() && f.ReceivedAt.Before(cutoffTime) {
			continue
		}

		srcIP := f.SrcAddr.String()
		dstIP := f.DstAddr.String()

		// Normalize: smaller IP is always "source" to merge A→B and B→A
		var key, nodeA, nodeB string
		if srcIP < dstIP {
			key = srcIP + "-" + dstIP
			nodeA = srcIP
			nodeB = dstIP
		} else {
			key = dstIP + "-" + srcIP
			nodeA = dstIP
			nodeB = srcIP
		}

		if link, ok := linkMap[key]; ok {
			link.Value += f.Bytes
			link.Packets += f.Packets
			link.Flows++
			protoCount[key][f.ProtocolName()] += f.Bytes
		} else {
			linkMap[key] = &SankeyLink{
				Source:  nodeA,
				Target:  nodeB,
				Value:   f.Bytes,
				Packets: f.Packets,
				Flows:   1,
			}
			protoCount[key] = map[string]uint64{f.ProtocolName(): f.Bytes}
		}
	}

	// Convert to slice and sort by value
	links := make([]SankeyLink, 0, len(linkMap))
	for key, link := range linkMap {
		// Find dominant protocol
		var maxProto string
		var maxBytes uint64
		for proto, bytes := range protoCount[key] {
			if bytes > maxBytes {
				maxBytes = bytes
				maxProto = proto
			}
		}
		link.Protocol = maxProto
		links = append(links, *link)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Value > links[j].Value
	})

	// Limit to topN
	if len(links) > topN {
		links = links[:topN]
	}

	// Build node set from filtered links
	nodeSet := make(map[string]string) // id -> type
	for _, link := range links {
		if _, ok := nodeSet[link.Source]; !ok {
			nodeSet[link.Source] = "source"
		}
		if _, ok := nodeSet[link.Target]; !ok {
			nodeSet[link.Target] = "target"
		}
	}

	// Convert to node slice
	nodes := make([]SankeyNode, 0, len(nodeSet))
	for id, typ := range nodeSet {
		label := id
		// DNS-Auflösung für IP-Adressen
		if ip := net.ParseIP(id); ip != nil {
			label = h.resolveIP(ip)
		}
		nodes = append(nodes, SankeyNode{
			ID:    id,
			Type:  typ,
			Label: label,
		})
	}

	return SankeyData{Nodes: nodes, Links: links}
}

// aggregateIPtoService creates Sankey data for IP-to-Service visualization
func (h *Handlers) aggregateIPtoService(filter *store.Filter, topN int, cutoffTime time.Time) SankeyData {
	// Get flows sorted by bytes (descending)
	flows := h.store.Query(filter, store.SortByBytes, false, 0)

	// Aggregate by source-service pair
	type linkKey struct {
		src     string
		service string
	}
	linkMap := make(map[linkKey]*SankeyLink)
	protoCount := make(map[linkKey]map[string]uint64)

	for i := range flows {
		f := &flows[i]

		// Zeit-Filter anwenden
		if !cutoffTime.IsZero() && f.ReceivedAt.Before(cutoffTime) {
			continue
		}

		// Determine service from destination port (most common case)
		service := resolver.GetServiceName(f.DstPort, f.Protocol)
		if service == "" {
			// Try source port (for responses)
			service = resolver.GetServiceName(f.SrcPort, f.Protocol)
		}
		if service == "" {
			// Fall back to port number
			service = strconv.Itoa(int(f.DstPort))
		}

		key := linkKey{src: f.SrcAddr.String(), service: service}

		if link, ok := linkMap[key]; ok {
			link.Value += f.Bytes
			link.Packets += f.Packets
			link.Flows++
			protoCount[key][f.ProtocolName()] += f.Bytes
		} else {
			linkMap[key] = &SankeyLink{
				Source:  f.SrcAddr.String(),
				Target:  service,
				Value:   f.Bytes,
				Packets: f.Packets,
				Flows:   1,
			}
			protoCount[key] = map[string]uint64{f.ProtocolName(): f.Bytes}
		}
	}

	// Convert to slice and sort by value
	links := make([]SankeyLink, 0, len(linkMap))
	for key, link := range linkMap {
		// Find dominant protocol
		var maxProto string
		var maxBytes uint64
		for proto, bytes := range protoCount[key] {
			if bytes > maxBytes {
				maxBytes = bytes
				maxProto = proto
			}
		}
		link.Protocol = maxProto
		links = append(links, *link)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Value > links[j].Value
	})

	// Limit to topN
	if len(links) > topN {
		links = links[:topN]
	}

	// Build node set from filtered links
	nodeSet := make(map[string]string) // id -> type
	for _, link := range links {
		if _, ok := nodeSet[link.Source]; !ok {
			nodeSet[link.Source] = "source"
		}
		if _, ok := nodeSet[link.Target]; !ok {
			nodeSet[link.Target] = "service"
		}
	}

	// Convert to node slice
	nodes := make([]SankeyNode, 0, len(nodeSet))
	for id, typ := range nodeSet {
		label := id
		// DNS-Auflösung für IP-Adressen (nicht für Services)
		if typ == "source" {
			if ip := net.ParseIP(id); ip != nil {
				label = h.resolveIP(ip)
			}
		}
		nodes = append(nodes, SankeyNode{
			ID:    id,
			Type:  typ,
			Label: label,
		})
	}

	return SankeyData{Nodes: nodes, Links: links}
}

// HandleFlows gibt rohe Flows mit optionalem Filter/Limit zurück
func (h *Handlers) HandleFlows(w http.ResponseWriter, r *http.Request) {
	filterStr := r.URL.Query().Get("filter")
	limit := 100
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}

	sortBy := store.SortByTime
	if s := r.URL.Query().Get("sort"); s != "" {
		switch s {
		case "bytes":
			sortBy = store.SortByBytes
		case "packets":
			sortBy = store.SortByPackets
		case "src":
			sortBy = store.SortBySrcIP
		case "dst":
			sortBy = store.SortByDstIP
		case "proto":
			sortBy = store.SortByProtocol
		}
	}

	ascending := r.URL.Query().Get("asc") == "true"

	// Parse filter
	var filter *store.Filter
	if filterStr != "" {
		f := store.ParseFilter(filterStr)
		if !f.IsValid() {
			writeError(w, http.StatusBadRequest, "Invalid filter", f.Error)
			return
		}
		filter = &f
	}

	flows := h.store.Query(filter, sortBy, ascending, limit)
	total := h.store.GetFlowCount()
	filtered := h.store.GetFilteredCount(filter)

	response := FlowsResponse{
		Flows:     make([]FlowResponse, len(flows)),
		Total:     total,
		Filtered:  filtered,
		Generated: time.Now(),
		Filter:    filterStr,
	}

	for i := range flows {
		f := &flows[i]
		service := resolver.GetServiceName(f.DstPort, f.Protocol)
		if service == "" {
			service = resolver.GetServiceName(f.SrcPort, f.Protocol)
		}
		response.Flows[i] = FlowToResponse(f, service)
	}

	writeJSON(w, response)
}

// HandleStats returns flow store statistics
func (h *Handlers) HandleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.store.GetStats()

	response := StatsResponse{
		TotalFlows:      stats.TotalFlows,
		TotalBytes:      stats.TotalBytes,
		TotalPackets:    stats.TotalPackets,
		FlowsPerSecond:  stats.FlowsPerSecond,
		BytesPerSecond:  stats.BytesPerSecond,
		V5Flows:         stats.V5Flows,
		V9Flows:         stats.V9Flows,
		IPFIXFlows:      stats.IPFIXFlows,
		UniqueExporters: stats.UniqueExporters,
		CurrentFlows:    h.store.GetFlowCount(),
		MaxFlows:        h.store.GetMaxFlows(),
		Generated:       time.Now(),
	}

	writeJSON(w, response)
}

// Helper functions

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, code int, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   message,
		Code:    code,
		Details: details,
	})
}

// ConvertFlowsToSankeyLinks is a utility to convert flows to sankey links (exported for cmd/sankey)
func ConvertFlowsToSankeyLinks(flows []types.Flow, mode string, topN int) ([]SankeyNode, []SankeyLink) {
	if mode == "ip-to-service" {
		return convertIPtoService(flows, topN)
	}
	return convertIPtoIP(flows, topN)
}

func convertIPtoIP(flows []types.Flow, topN int) ([]SankeyNode, []SankeyLink) {
	type linkKey struct {
		src string
		dst string
	}
	linkMap := make(map[linkKey]*SankeyLink)
	protoCount := make(map[linkKey]map[string]uint64)

	for i := range flows {
		f := &flows[i]
		key := linkKey{src: f.SrcAddr.String(), dst: f.DstAddr.String()}

		if link, ok := linkMap[key]; ok {
			link.Value += f.Bytes
			link.Packets += f.Packets
			link.Flows++
			protoCount[key][f.ProtocolName()] += f.Bytes
		} else {
			linkMap[key] = &SankeyLink{
				Source:  f.SrcAddr.String(),
				Target:  f.DstAddr.String(),
				Value:   f.Bytes,
				Packets: f.Packets,
				Flows:   1,
			}
			protoCount[key] = map[string]uint64{f.ProtocolName(): f.Bytes}
		}
	}

	links := make([]SankeyLink, 0, len(linkMap))
	for key, link := range linkMap {
		var maxProto string
		var maxBytes uint64
		for proto, bytes := range protoCount[key] {
			if bytes > maxBytes {
				maxBytes = bytes
				maxProto = proto
			}
		}
		link.Protocol = maxProto
		links = append(links, *link)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Value > links[j].Value
	})

	if len(links) > topN {
		links = links[:topN]
	}

	nodeSet := make(map[string]string)
	for _, link := range links {
		if _, ok := nodeSet[link.Source]; !ok {
			nodeSet[link.Source] = "source"
		}
		if _, ok := nodeSet[link.Target]; !ok {
			nodeSet[link.Target] = "target"
		}
	}

	nodes := make([]SankeyNode, 0, len(nodeSet))
	for id, typ := range nodeSet {
		nodes = append(nodes, SankeyNode{ID: id, Type: typ, Label: id})
	}

	return nodes, links
}

func convertIPtoService(flows []types.Flow, topN int) ([]SankeyNode, []SankeyLink) {
	type linkKey struct {
		src     string
		service string
	}
	linkMap := make(map[linkKey]*SankeyLink)
	protoCount := make(map[linkKey]map[string]uint64)

	for i := range flows {
		f := &flows[i]
		service := resolver.GetServiceName(f.DstPort, f.Protocol)
		if service == "" {
			service = resolver.GetServiceName(f.SrcPort, f.Protocol)
		}
		if service == "" {
			service = strconv.Itoa(int(f.DstPort))
		}

		key := linkKey{src: f.SrcAddr.String(), service: service}

		if link, ok := linkMap[key]; ok {
			link.Value += f.Bytes
			link.Packets += f.Packets
			link.Flows++
			protoCount[key][f.ProtocolName()] += f.Bytes
		} else {
			linkMap[key] = &SankeyLink{
				Source:  f.SrcAddr.String(),
				Target:  service,
				Value:   f.Bytes,
				Packets: f.Packets,
				Flows:   1,
			}
			protoCount[key] = map[string]uint64{f.ProtocolName(): f.Bytes}
		}
	}

	links := make([]SankeyLink, 0, len(linkMap))
	for key, link := range linkMap {
		var maxProto string
		var maxBytes uint64
		for proto, bytes := range protoCount[key] {
			if bytes > maxBytes {
				maxBytes = bytes
				maxProto = proto
			}
		}
		link.Protocol = maxProto
		links = append(links, *link)
	}

	sort.Slice(links, func(i, j int) bool {
		return links[i].Value > links[j].Value
	})

	if len(links) > topN {
		links = links[:topN]
	}

	nodeSet := make(map[string]string)
	for _, link := range links {
		if _, ok := nodeSet[link.Source]; !ok {
			nodeSet[link.Source] = "source"
		}
		if _, ok := nodeSet[link.Target]; !ok {
			nodeSet[link.Target] = "service"
		}
	}

	nodes := make([]SankeyNode, 0, len(nodeSet))
	for id, typ := range nodeSet {
		nodes = append(nodes, SankeyNode{ID: id, Type: typ, Label: id})
	}

	return nodes, links
}

// aggregateFirewall erstellt Sankey-Daten für Firewall-Visualisierung
// 4-Spalten Layout: [Left IP] → [Left IF] → [Right IF] → [Right IP]
// leftIF/rightIF: 0 = automatisch (rightIF=WAN, leftIF=alle anderen)
// leftExporter/rightExporter: Exporter-IP Filter (leer = alle)
func (h *Handlers) aggregateFirewall(filter *store.Filter, topN int, cutoffTime time.Time, leftIF, rightIF uint16, leftExporter, rightExporter string) SankeyData {
	flows := h.store.Query(filter, store.SortByBytes, false, 0)

	// Zeit-Filter anwenden (früh filtern für Interface-Erkennung)
	if !cutoffTime.IsZero() {
		filtered := flows[:0]
		for i := range flows {
			if !flows[i].ReceivedAt.Before(cutoffTime) {
				filtered = append(filtered, flows[i])
			}
		}
		flows = filtered
	}

	// Cross-Exporter Modus erkennen
	crossExporter := leftExporter != "" && rightExporter != "" && leftExporter != rightExporter

	// Flows nach Exporter aufteilen wenn Cross-Exporter Modus
	var leftFlows, rightFlows []types.Flow
	if crossExporter {
		for i := range flows {
			expIP := flows[i].ExporterIP.String()
			if expIP == leftExporter {
				leftFlows = append(leftFlows, flows[i])
			}
			if expIP == rightExporter {
				rightFlows = append(rightFlows, flows[i])
			}
		}
	} else {
		// Single-Exporter Modus: alle Flows verwenden
		// Optional nach Exporter filtern
		if leftExporter != "" {
			for i := range flows {
				if flows[i].ExporterIP.String() == leftExporter {
					leftFlows = append(leftFlows, flows[i])
				}
			}
		} else {
			leftFlows = flows
		}
		rightFlows = leftFlows
	}

	// Wenn rightIF nicht gesetzt, WAN automatisch erkennen (vom rechten Exporter)
	if rightIF == 0 {
		rightIF = guessWANFromFlows(rightFlows)
	}
	// Wenn leftIF nicht gesetzt und Single-Exporter, WAN für linken verwenden
	if leftIF == 0 && !crossExporter {
		// Im Single-Exporter Modus: kein spezieller leftIF Filter
	}

	// Schritt 1: End-zu-End Verbindungen nach Traffic aggregieren
	type connectionKey struct {
		leftIP   string
		rightIP  string
		leftIf   uint16
		rightIf  uint16
		exporter string // Exporter der diesen Flow gemeldet hat
	}
	type connectionStats struct {
		bytes    uint64
		packets  uint64
		flows    int
		inferred bool // True wenn von anderem Exporter inferiert
	}
	connections := make(map[connectionKey]*connectionStats)

	// Hilfsfunktion zum Verarbeiten von Flows
	processFlows := func(flowList []types.Flow, isLeft bool, targetIF uint16) {
		for i := range flowList {
			f := &flowList[i]
			if f.InputIf == 0 && f.OutputIf == 0 {
				continue
			}

			var key connectionKey
			var matched bool
			expIP := f.ExporterIP.String()

			// Traffic von links nach rechts: InputIf=left, OutputIf=right
			if f.OutputIf == targetIF && f.InputIf != targetIF && f.InputIf > 0 {
				if leftIF == 0 || f.InputIf == leftIF {
					key = connectionKey{
						leftIP:   f.SrcAddr.String(),
						rightIP:  f.DstAddr.String(),
						leftIf:   f.InputIf,
						rightIf:  targetIF,
						exporter: expIP,
					}
					matched = true
				}
			} else if f.InputIf == targetIF && f.OutputIf != targetIF && f.OutputIf > 0 {
				// Traffic von rechts nach links: InputIf=right, OutputIf=left
				if leftIF == 0 || f.OutputIf == leftIF {
					key = connectionKey{
						leftIP:   f.DstAddr.String(),
						rightIP:  f.SrcAddr.String(),
						leftIf:   f.OutputIf,
						rightIf:  targetIF,
						exporter: expIP,
					}
					matched = true
				}
			}

			if !matched {
				continue
			}

			if stats, ok := connections[key]; ok {
				stats.bytes += f.Bytes
				stats.packets += f.Packets
				stats.flows++
			} else {
				connections[key] = &connectionStats{
					bytes:   f.Bytes,
					packets: f.Packets,
					flows:   1,
				}
			}
		}
	}

	if crossExporter {
		// Cross-Exporter: Linke Flows mit linkem IF verarbeiten
		// Wir brauchen das WAN des linken Exporters als "Ausgang"
		leftWAN := guessWANFromFlows(leftFlows)
		processFlows(leftFlows, true, leftWAN)

		// Rechte Flows mit rechtem IF (WAN) verarbeiten
		processFlows(rightFlows, false, rightIF)
	} else {
		// Single-Exporter Modus
		processFlows(leftFlows, true, rightIF)
	}

	// Schritt 2: Top N Verbindungen nach Bytes ermitteln
	type rankedConnection struct {
		key   connectionKey
		stats *connectionStats
	}
	ranked := make([]rankedConnection, 0, len(connections))
	for k, v := range connections {
		ranked = append(ranked, rankedConnection{key: k, stats: v})
	}
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].stats.bytes > ranked[j].stats.bytes
	})
	if len(ranked) > topN {
		ranked = ranked[:topN]
	}

	// Schritt 3: Links nur für Top N Verbindungen erstellen
	type linkKey struct {
		from     string
		to       string
		inferred bool
	}
	linkMap := make(map[linkKey]*SankeyLink)

	// Map für IP → Interface Zuordnung (für Sortierung)
	leftIPtoIF := make(map[string]uint16)
	rightIPtoIF := make(map[string]uint16)

	// Interface-Knoten Namen mit Exporter-Prefix wenn Cross-Exporter
	makeIfNode := func(ifID uint16, exporterIP string) string {
		if crossExporter && exporterIP != "" {
			// Kürze Exporter-IP für bessere Lesbarkeit
			shortExp := exporterIP
			if ip := net.ParseIP(exporterIP); ip != nil {
				if resolved := h.resolveIP(ip); resolved != exporterIP {
					shortExp = resolved
				} else if ip4 := ip.To4(); ip4 != nil {
					// Nur letzte zwei Oktette
					shortExp = fmt.Sprintf("%d.%d", ip4[2], ip4[3])
				}
			}
			return fmt.Sprintf("%s:IF%d", shortExp, ifID)
		}
		return fmt.Sprintf("IF:%d", ifID)
	}

	for _, conn := range ranked {
		leftNode := makeIfNode(conn.key.leftIf, conn.key.exporter)
		rightNode := makeIfNode(conn.key.rightIf, conn.key.exporter)

		leftIPtoIF[conn.key.leftIP] = conn.key.leftIf
		rightIPtoIF[conn.key.rightIP] = conn.key.rightIf

		inferred := conn.stats.inferred

		// Link 1: Left IP → Left IF
		key1 := linkKey{from: conn.key.leftIP, to: leftNode, inferred: inferred}
		if link, ok := linkMap[key1]; ok {
			link.Value += conn.stats.bytes
			link.Packets += conn.stats.packets
			link.Flows += conn.stats.flows
		} else {
			linkMap[key1] = &SankeyLink{
				Source:   conn.key.leftIP,
				Target:   leftNode,
				Value:    conn.stats.bytes,
				Packets:  conn.stats.packets,
				Flows:    conn.stats.flows,
				Inferred: inferred,
			}
		}

		// Link 2: Left IF → Right IF
		key2 := linkKey{from: leftNode, to: rightNode, inferred: inferred}
		if link, ok := linkMap[key2]; ok {
			link.Value += conn.stats.bytes
			link.Packets += conn.stats.packets
			link.Flows += conn.stats.flows
		} else {
			linkMap[key2] = &SankeyLink{
				Source:   leftNode,
				Target:   rightNode,
				Value:    conn.stats.bytes,
				Packets:  conn.stats.packets,
				Flows:    conn.stats.flows,
				Inferred: inferred,
			}
		}

		// Link 3: Right IF → Right IP
		key3 := linkKey{from: rightNode, to: conn.key.rightIP, inferred: inferred}
		if link, ok := linkMap[key3]; ok {
			link.Value += conn.stats.bytes
			link.Packets += conn.stats.packets
			link.Flows += conn.stats.flows
		} else {
			linkMap[key3] = &SankeyLink{
				Source:   rightNode,
				Target:   conn.key.rightIP,
				Value:    conn.stats.bytes,
				Packets:  conn.stats.packets,
				Flows:    conn.stats.flows,
				Inferred: inferred,
			}
		}
	}

	// In Slice umwandeln
	allLinks := make([]SankeyLink, 0, len(linkMap))
	for _, link := range linkMap {
		allLinks = append(allLinks, *link)
	}

	// Hilfsfunktion: Prüfen ob ein Knoten ein Interface-Knoten ist
	isIfNode := func(id string) bool {
		// Matches "IF:X" oder "something:IFX"
		return len(id) >= 3 && (id[:3] == "IF:" || strings.Contains(id, ":IF"))
	}

	// Hilfsfunktion: Interface-ID aus Knoten-ID extrahieren
	extractIfID := func(id string) int {
		var ifID int
		if strings.HasPrefix(id, "IF:") {
			fmt.Sscanf(id, "IF:%d", &ifID)
		} else if idx := strings.Index(id, ":IF"); idx >= 0 {
			fmt.Sscanf(id[idx:], ":IF%d", &ifID)
		}
		return ifID
	}

	// Build nodes with types based on position in the chain
	nodeSet := make(map[string]string)
	rightIfNodes := make(map[string]bool) // Track right-side IF nodes

	// Erst alle Ziel-IF-Knoten markieren (die sind rechte IFs)
	for _, link := range allLinks {
		if isIfNode(link.Target) {
			// Ein IF das Ziel eines anderen IF ist = rechtes IF
			if isIfNode(link.Source) {
				rightIfNodes[link.Target] = true
			}
		}
	}

	for _, link := range allLinks {
		// Classify source node
		if _, ok := nodeSet[link.Source]; !ok {
			if isIfNode(link.Source) {
				if rightIfNodes[link.Source] {
					nodeSet[link.Source] = "right-if"
				} else {
					nodeSet[link.Source] = "left-if"
				}
			} else {
				nodeSet[link.Source] = "left"
			}
		}
		// Classify target node
		if _, ok := nodeSet[link.Target]; !ok {
			if isIfNode(link.Target) {
				if rightIfNodes[link.Target] {
					nodeSet[link.Target] = "right-if"
				} else {
					nodeSet[link.Target] = "left-if"
				}
			} else {
				nodeSet[link.Target] = "right"
			}
		}
	}

	nodes := make([]SankeyNode, 0, len(nodeSet))
	for id, typ := range nodeSet {
		label := id
		sortKey := 0

		// DNS-Auflösung nur für IP-Adressen (nicht für IF: Knoten)
		if typ == "left" {
			if ip := net.ParseIP(id); ip != nil {
				label = h.resolveIP(ip)
			}
			// SortKey = zugehöriges Interface
			if ifID, ok := leftIPtoIF[id]; ok {
				sortKey = int(ifID)
			}
		} else if typ == "right" {
			if ip := net.ParseIP(id); ip != nil {
				label = h.resolveIP(ip)
			}
			if ifID, ok := rightIPtoIF[id]; ok {
				sortKey = int(ifID)
			}
		} else if typ == "left-if" || typ == "right-if" {
			sortKey = extractIfID(id)
		}

		nodes = append(nodes, SankeyNode{ID: id, Type: typ, Label: label, SortKey: sortKey})
	}

	return SankeyData{Nodes: nodes, Links: allLinks}
}

// guessWANFromFlows ermittelt das WAN-Interface aus den Flows
func guessWANFromFlows(flows []types.Flow) uint16 {
	ifacePublicIPs := make(map[uint16]map[string]bool)

	for i := range flows {
		f := &flows[i]
		if !isPrivateIP(f.SrcAddr) && f.InputIf > 0 {
			if ifacePublicIPs[f.InputIf] == nil {
				ifacePublicIPs[f.InputIf] = make(map[string]bool)
			}
			ifacePublicIPs[f.InputIf][f.SrcAddr.String()] = true
		}
		if !isPrivateIP(f.DstAddr) && f.OutputIf > 0 {
			if ifacePublicIPs[f.OutputIf] == nil {
				ifacePublicIPs[f.OutputIf] = make(map[string]bool)
			}
			ifacePublicIPs[f.OutputIf][f.DstAddr.String()] = true
		}
	}

	var wanIF uint16
	maxCount := 0
	for ifID, ips := range ifacePublicIPs {
		if len(ips) > maxCount {
			maxCount = len(ips)
			wanIF = ifID
		}
	}
	return wanIF
}

// isPrivateIP checks if an IP is in a private range
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		if len(ip) >= 1 {
			if ip[0] == 0xfd {
				return true
			}
			if ip[0] == 0xfe && len(ip) >= 2 && (ip[1]&0xc0) == 0x80 {
				return true
			}
		}
		return false
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	return false
}

// ipToSubnet converts an IP to its /24 (IPv4) or /64 (IPv6) subnet
func ipToSubnet(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	ip4 := ip.To4()
	if ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	}
	if len(ip) >= 8 {
		return fmt.Sprintf("%x:%x:%x:%x::/64",
			uint16(ip[0])<<8|uint16(ip[1]),
			uint16(ip[2])<<8|uint16(ip[3]),
			uint16(ip[4])<<8|uint16(ip[5]),
			uint16(ip[6])<<8|uint16(ip[7]))
	}
	return ip.String()
}

// isSubnetPrivate checks if a subnet string represents a private network
func isSubnetPrivate(subnet string) bool {
	if len(subnet) < 4 {
		return false
	}
	if subnet[:3] == "10." {
		return true
	}
	if len(subnet) >= 7 && subnet[:7] == "192.168" {
		return true
	}
	if len(subnet) >= 4 && subnet[:4] == "172." {
		if len(subnet) >= 6 {
			second := subnet[4:6]
			if second == "16" || second == "17" || second == "18" || second == "19" ||
				second == "20" || second == "21" || second == "22" || second == "23" ||
				second == "24" || second == "25" || second == "26" || second == "27" ||
				second == "28" || second == "29" || second == "30" || second == "31" {
				return true
			}
		}
	}
	if len(subnet) >= 2 && (subnet[:2] == "fd" || subnet[:2] == "FD") {
		return true
	}
	return false
}

// HandleInterfaces gibt eine Liste aller bekannten Interfaces zurück, gruppiert nach Exporter
func (h *Handlers) HandleInterfaces(w http.ResponseWriter, r *http.Request) {
	flows := h.store.Query(nil, store.SortByBytes, false, 0)

	// Interface-Statistiken pro Exporter sammeln
	type ifStats struct {
		flowCount  int
		bytes      uint64
		publicIPs  map[string]bool
		privateIPs map[string]bool
		subnets    map[string]int // Subnetz → Anzahl IPs
	}
	// Key: "exporterIP:interfaceID"
	type exporterIfKey struct {
		exporterIP string
		ifID       uint16
	}
	ifMap := make(map[exporterIfKey]*ifStats)
	exporterSet := make(map[string]bool)

	for i := range flows {
		f := &flows[i]
		exporterIP := f.ExporterIP.String()
		exporterSet[exporterIP] = true

		// InputIf verarbeiten
		if f.InputIf > 0 {
			key := exporterIfKey{exporterIP: exporterIP, ifID: f.InputIf}
			if ifMap[key] == nil {
				ifMap[key] = &ifStats{
					publicIPs:  make(map[string]bool),
					privateIPs: make(map[string]bool),
					subnets:    make(map[string]int),
				}
			}
			stats := ifMap[key]
			stats.flowCount++
			stats.bytes += f.Bytes
			// SrcAddr kam über dieses Interface rein
			ipStr := f.SrcAddr.String()
			if isPrivateIP(f.SrcAddr) {
				if !stats.privateIPs[ipStr] {
					stats.privateIPs[ipStr] = true
					subnet := ipToSubnet(f.SrcAddr)
					stats.subnets[subnet]++
				}
			} else {
				stats.publicIPs[ipStr] = true
			}
		}

		// OutputIf verarbeiten
		if f.OutputIf > 0 {
			key := exporterIfKey{exporterIP: exporterIP, ifID: f.OutputIf}
			if ifMap[key] == nil {
				ifMap[key] = &ifStats{
					publicIPs:  make(map[string]bool),
					privateIPs: make(map[string]bool),
					subnets:    make(map[string]int),
				}
			}
			stats := ifMap[key]
			stats.flowCount++
			stats.bytes += f.Bytes
			ipStr := f.DstAddr.String()
			if isPrivateIP(f.DstAddr) {
				if !stats.privateIPs[ipStr] {
					stats.privateIPs[ipStr] = true
					subnet := ipToSubnet(f.DstAddr)
					stats.subnets[subnet]++
				}
			} else {
				stats.publicIPs[ipStr] = true
			}
		}
	}

	// WAN pro Exporter ermitteln
	exporterWAN := make(map[string]uint16)
	for exporterIP := range exporterSet {
		// Flows dieses Exporters filtern
		var exporterFlows []types.Flow
		for i := range flows {
			if flows[i].ExporterIP.String() == exporterIP {
				exporterFlows = append(exporterFlows, flows[i])
			}
		}
		exporterWAN[exporterIP] = guessWANFromFlows(exporterFlows)
	}

	// Globales WAN (Legacy)
	globalWAN := guessWANFromFlows(flows)

	// Exporters erstellen
	exporterList := make([]string, 0, len(exporterSet))
	for exp := range exporterSet {
		exporterList = append(exporterList, exp)
	}
	sort.Strings(exporterList)

	exporters := make([]ExporterInfo, 0, len(exporterList))
	var flatInterfaces []InterfaceInfo // Legacy flache Liste

	for _, exporterIP := range exporterList {
		wanID := exporterWAN[exporterIP]

		// Interfaces dieses Exporters sammeln
		var interfaces []InterfaceInfo
		for key, stats := range ifMap {
			if key.exporterIP != exporterIP {
				continue
			}

			// Häufigstes Subnetz ermitteln
			var topSubnet string
			var topSubnetIPs int
			for subnet, count := range stats.subnets {
				if count > topSubnetIPs {
					topSubnetIPs = count
					topSubnet = subnet
				}
			}

			ifInfo := InterfaceInfo{
				ID:           key.ifID,
				ExporterIP:   exporterIP,
				FlowCount:    stats.flowCount,
				Bytes:        stats.bytes,
				IsWAN:        key.ifID == wanID,
				PublicIPs:    len(stats.publicIPs),
				PrivateIPs:   len(stats.privateIPs),
				TopSubnet:    topSubnet,
				TopSubnetIPs: topSubnetIPs,
			}
			interfaces = append(interfaces, ifInfo)
			flatInterfaces = append(flatInterfaces, ifInfo)
		}

		// Nach Interface-ID sortieren
		sort.Slice(interfaces, func(i, j int) bool {
			return interfaces[i].ID < interfaces[j].ID
		})

		// DNS-Auflösung für Exporter
		exporterName := exporterIP
		if ip := net.ParseIP(exporterIP); ip != nil {
			exporterName = h.resolveIP(ip)
		}

		exporters = append(exporters, ExporterInfo{
			IP:         exporterIP,
			Name:       exporterName,
			Interfaces: interfaces,
			WanID:      wanID,
		})
	}

	// Legacy flache Liste sortieren
	sort.Slice(flatInterfaces, func(i, j int) bool {
		if flatInterfaces[i].ExporterIP != flatInterfaces[j].ExporterIP {
			return flatInterfaces[i].ExporterIP < flatInterfaces[j].ExporterIP
		}
		return flatInterfaces[i].ID < flatInterfaces[j].ID
	})

	writeJSON(w, InterfacesResponse{
		Exporters:  exporters,
		Interfaces: flatInterfaces,
		WanID:      globalWAN,
		Generated:  time.Now(),
	})
}
