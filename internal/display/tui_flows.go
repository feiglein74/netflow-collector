package display

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/resolver"
	"netflow-collector/internal/store"
	"netflow-collector/pkg/types"
)

// showFlowDetail displays the detail view for the selected flow
func (t *TUI) showFlowDetail() {
	row, _ := t.table.GetSelection()
	if row <= 0 || row > len(t.currentFlows) {
		return
	}

	flow := t.currentFlows[row-1] // -1 for header row
	t.showDetail = true
	t.detailFlowKey = flow.FlowKey()
	t.detailConvKey = "" // Clear conversation key

	// Mark this flow as accessed for LRU protection
	t.store.MarkFlowAccessed(flow.FlowKey())

	t.updateFlowDetailContent(&flow)
	t.layout.Clear()
	t.layout.AddItem(t.detailView, 0, 1, true)
	t.app.SetFocus(t.detailView)
}

// updateFlowDetailContent updates the content of the flow detail view
func (t *TUI) updateFlowDetailContent(flow *types.Flow) {
	text := fmt.Sprintf(`[yellow]═══ Network Layer ═══[white]
[green]Source IP:[white]      %s
[green]Destination IP:[white] %s
[green]Protocol:[white]       %s (%d)

[yellow]═══ Transport Layer ═══[white]
[green]Source Port:[white]    %d  %s
[green]Dest Port:[white]      %d  %s
[green]TCP Flags:[white]      %s

[yellow]═══ Statistics ═══[white]
[green]Bytes:[white]          %s
[green]Packets:[white]        %d
[green]Duration:[white]       %v

[yellow]═══ Routing Info ═══[white]
[green]Source AS:[white]      %d
[green]Dest AS:[white]        %d
[green]Input Interface:[white]  %d
[green]Output Interface:[white] %d

[yellow]═══ Metadata ═══[white]
[green]NetFlow Version:[white] %s
[green]Exporter IP:[white]    %s
[green]Flow Start:[white]     %s
[green]Flow End:[white]       %s
[green]Received:[white]       %s

[gray]Press Esc to close[white]`,
		flow.SrcAddr,
		flow.DstAddr,
		flow.ProtocolName(), flow.Protocol,
		flow.SrcPort, resolver.GetServiceName(flow.SrcPort, flow.Protocol),
		flow.DstPort, resolver.GetServiceName(flow.DstPort, flow.Protocol),
		flow.TCPFlagsString(),
		formatBytes(flow.Bytes),
		flow.Packets,
		flow.Duration(),
		flow.SrcAS,
		flow.DstAS,
		flow.InputIf,
		flow.OutputIf,
		flow.Version.String(),
		flow.ExporterIP,
		flow.StartTime.Format("2006-01-02 15:04:05"),
		flow.EndTime.Format("2006-01-02 15:04:05"),
		flow.ReceivedAt.Format("2006-01-02 15:04:05"),
	)
	t.detailView.SetText(text)
}

// hideFlowDetail hides the flow detail view and returns to the main view
func (t *TUI) hideFlowDetail() {
	t.showDetail = false
	t.detailFlowKey = ""
	t.detailConvKey = ""
	t.layout.Clear()
	topRow := tview.NewFlex().
		AddItem(t.statsView, 0, 2, false).
		AddItem(t.filterView, 0, 1, false)
	t.layout.AddItem(t.filterInput, 3, 0, true)
	t.layout.AddItem(topRow, 7, 0, false)
	t.layout.AddItem(t.table, 0, 1, false)
	t.app.SetFocus(t.table)
}

// updateTableFlows updates the flow table with current data
func (t *TUI) updateTableFlows() {
	// Get flows with current filter and sort
	var flows []types.Flow
	if t.aggregateFlows {
		flows = t.store.QueryAggregatedFlows(&t.filter, t.sortField, t.sortAsc, 1000)
	} else {
		flows = t.store.Query(&t.filter, t.sortField, t.sortAsc, 1000)
	}

	// Save for detail view access
	t.currentFlows = flows

	// Remember current selection
	selectedRow, _ := t.table.GetSelection()

	// Clear existing rows (keep header)
	rowCount := t.table.GetRowCount()
	for i := rowCount - 1; i > 0; i-- {
		t.table.RemoveRow(i)
	}

	cols := t.getColumns()
	flexMaxWidth := t.getFlexColumnMaxWidth()

	// Helper to truncate and pad text to column width
	formatCol := func(s string, colIdx int, col columnDef, isEndpoint bool) string {
		// Truncate flexible columns if string is too long
		if col.flex && len(s) > flexMaxWidth {
			if isEndpoint {
				s = truncateEndpoint(s, flexMaxWidth)
			} else {
				s = s[:flexMaxWidth-1] + "…"
			}
		}
		width := t.getColWidth(colIdx, s, col.minWidth)
		if len(s) < width {
			return s + strings.Repeat(" ", width-len(s))
		}
		return s
	}

	// Add flow rows
	for i, flow := range flows {
		row := i + 1 // +1 for header

		// Format source and destination
		src := t.formatFlowEndpoint(flow.SrcAddr.String(), flow.SrcPort, flow.Protocol)
		dst := t.formatFlowEndpoint(flow.DstAddr.String(), flow.DstPort, flow.Protocol)
		timeStr := flow.ReceivedAt.Format("15:04:05")
		ageStr := formatAge(time.Since(flow.ReceivedAt))

		// Detect service (use the lower port as it's usually the server)
		service := ""
		if t.showService {
			if flow.SrcPort < flow.DstPort && flow.SrcPort > 0 {
				service = resolver.GetServiceName(flow.SrcPort, flow.Protocol)
			} else if flow.DstPort > 0 {
				service = resolver.GetServiceName(flow.DstPort, flow.Protocol)
			}
			if service == "" && flow.SrcPort > 0 {
				service = resolver.GetServiceName(flow.SrcPort, flow.Protocol)
			}
		}

		protoColor := tcell.ColorWhite
		switch flow.Protocol {
		case 6:
			protoColor = tcell.ColorLightCyan
		case 17:
			protoColor = tcell.ColorLightYellow
		case 1:
			protoColor = tcell.ColorLightPink
		}

		// Build protocol/service display
		protoDisplay := flow.ProtocolName()
		if service != "" {
			protoDisplay = service
		}

		col := 0
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(src, col, cols[col], true)).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(dst, col, cols[col], true)).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(protoDisplay, col, cols[col], false)).SetTextColor(protoColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(formatBytes(flow.Bytes), col, cols[col], false)).SetAlign(tview.AlignRight).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(fmt.Sprintf("%d", flow.Packets), col, cols[col], false)).SetAlign(tview.AlignRight).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(timeStr, col, cols[col], false)).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(ageStr, col, cols[col], false)).SetExpansion(1))
	}

	// Restore selection if valid
	if selectedRow > 0 && selectedRow < t.table.GetRowCount() {
		t.table.Select(selectedRow, 0)
	} else if t.table.GetRowCount() > 1 {
		t.table.Select(1, 0)
	}
}

// formatFlowEndpoint formats IP:port with optional DNS resolution
func (t *TUI) formatFlowEndpoint(ip string, port uint16, protocol uint8) string {
	display := ip

	// Try DNS resolution if enabled
	if t.showDNS {
		parsedIP := parseIP(ip)
		if parsedIP != nil {
			if hostname, ok := t.resolver.GetCached(parsedIP); ok {
				display = hostname
			} else {
				// Trigger async lookup for next refresh
				t.resolver.Resolve(parsedIP)
			}
		}
	}

	if port == 0 {
		return display
	}

	return fmt.Sprintf("%s:%d", display, port)
}

// getSeenServices returns unique service names from current flows
func (t *TUI) getSeenServices() []string {
	seen := make(map[string]bool)
	var services []string

	for _, flow := range t.currentFlows {
		// Check source port service
		if svc := resolver.GetServiceName(flow.SrcPort, flow.Protocol); svc != "" {
			if !seen[svc] {
				seen[svc] = true
				services = append(services, svc)
			}
		}
		// Check dest port service
		if svc := resolver.GetServiceName(flow.DstPort, flow.Protocol); svc != "" {
			if !seen[svc] {
				seen[svc] = true
				services = append(services, svc)
			}
		}
		// Also add protocol name for things like ICMP
		protoName := strings.ToLower(flow.ProtocolName())
		if !seen[protoName] {
			seen[protoName] = true
			services = append(services, protoName)
		}
	}

	if len(services) > 15 {
		services = services[:15]
	}
	return services
}

// getSeenPorts returns unique port numbers from current flows as strings
func (t *TUI) getSeenPorts() []string {
	seen := make(map[uint16]bool)
	var ports []string

	for _, flow := range t.currentFlows {
		if flow.SrcPort > 0 && !seen[flow.SrcPort] {
			seen[flow.SrcPort] = true
			ports = append(ports, fmt.Sprintf("%d", flow.SrcPort))
		}
		if flow.DstPort > 0 && !seen[flow.DstPort] {
			seen[flow.DstPort] = true
			ports = append(ports, fmt.Sprintf("%d", flow.DstPort))
		}
	}

	if len(ports) > 15 {
		ports = ports[:15]
	}
	return ports
}

// getSeenIPs returns unique IP addresses from current flows
func (t *TUI) getSeenIPs() []string {
	seen := make(map[string]bool)
	var ips []string

	for _, flow := range t.currentFlows {
		srcIP := flow.SrcAddr.String()
		dstIP := flow.DstAddr.String()

		if !seen[srcIP] {
			seen[srcIP] = true
			ips = append(ips, srcIP)
		}
		if !seen[dstIP] {
			seen[dstIP] = true
			ips = append(ips, dstIP)
		}
	}

	if len(ips) > 15 {
		ips = ips[:15]
	}
	return ips
}

// getSeenInterfaces returns unique interface IDs from current flows
func (t *TUI) getSeenInterfaces() []string {
	seen := make(map[uint16]bool)
	var ifaces []string

	for _, flow := range t.currentFlows {
		if flow.InputIf > 0 && !seen[flow.InputIf] {
			seen[flow.InputIf] = true
			ifaces = append(ifaces, fmt.Sprintf("%d", flow.InputIf))
		}
		if flow.OutputIf > 0 && !seen[flow.OutputIf] {
			seen[flow.OutputIf] = true
			ifaces = append(ifaces, fmt.Sprintf("%d", flow.OutputIf))
		}
	}

	if len(ifaces) > 15 {
		ifaces = ifaces[:15]
	}
	return ifaces
}

// refreshDetailContent updates the detail view with fresh data
func (t *TUI) refreshDetailContent() {
	// Query without filter to ensure we find the item even if filter changed
	emptyFilter := store.Filter{}

	// Check which type of detail is being shown based on which key is set
	if t.detailConvKey != "" {
		// Refresh conversation data and find matching one
		conversations := t.store.QueryConversations(&emptyFilter, t.sortField, t.sortAsc, 10000)
		for i := range conversations {
			if conversations[i].Key() == t.detailConvKey {
				t.updateConversationDetailContent(&conversations[i])
				return
			}
		}
	} else if t.detailFlowKey != "" {
		// Refresh flow data and find matching one
		flows := t.store.Query(&emptyFilter, t.sortField, t.sortAsc, 10000)
		for i := range flows {
			if flows[i].FlowKey() == t.detailFlowKey {
				t.updateFlowDetailContent(&flows[i])
				return
			}
		}
	}
}
