package display

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/store"
)

// InterfaceStats holds statistics for a single interface
type InterfaceStats struct {
	ID              uint16
	InFlows         int
	OutFlows        int
	InBytes         uint64
	OutBytes        uint64
	PrivateIPs      map[string]bool // Set of private IPv4s seen on this interface
	PrivateIPv6s    map[string]bool // Set of private/ULA IPv6s seen on this interface
	PublicIPs       map[string]bool // Set of public IPv4s seen on this interface
	PublicIPv6s     map[string]bool // Set of public IPv6s seen on this interface
	LastSubnet      string          // Last calculated IPv4 subnet
	LastSubnetV6    string          // Last calculated IPv6 subnet
	SubnetChanged   time.Time       // When IPv4 subnet last changed
	SubnetV6Changed time.Time       // When IPv6 subnet last changed
}

// setupInterfaceTableHeaders sets up the interface table headers
func (t *TUI) setupInterfaceTableHeaders() {
	headers := []string{"*", "Interface", "Subnet (guessed)", "Int", "Ext", "In Flows", "Out Flows", "Total", "In Bytes", "Out Bytes"}
	for i, h := range headers {
		expansion := 1
		if i == 0 {
			expansion = 0 // Small column for marker
		}
		cell := tview.NewTableCell(h).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false).
			SetExpansion(expansion)
		t.interfaceTable.SetCell(0, i, cell)
	}
}

// switchPage toggles between flows and interfaces page
func (t *TUI) switchPage() {
	if t.currentPage == 0 {
		t.currentPage = 1
		t.pages.SwitchToPage("interfaces")
		t.app.SetFocus(t.interfaceTable)
	} else {
		t.currentPage = 0
		t.pages.SwitchToPage("flows")
		t.app.SetFocus(t.filterInput)
	}
}

// updateInterfaceStats updates cumulative interface statistics from new flows
func (t *TUI) updateInterfaceStats() {
	// Get all flows and only count those received after our last update
	allFlows := t.store.Query(nil, store.SortByTime, false, 100000)

	for _, flow := range allFlows {
		// Only count flows we haven't seen yet
		if !flow.ReceivedAt.After(t.lastInterfaceUpdate) {
			continue
		}

		// Input interface - traffic coming IN, so SrcAddr is "behind" this interface
		if flow.InputIf > 0 {
			if _, ok := t.interfaceStats[flow.InputIf]; !ok {
				t.interfaceStats[flow.InputIf] = &InterfaceStats{
					ID:           flow.InputIf,
					PrivateIPs:   make(map[string]bool),
					PrivateIPv6s: make(map[string]bool),
					PublicIPs:    make(map[string]bool),
					PublicIPv6s:  make(map[string]bool),
				}
			}
			stats := t.interfaceStats[flow.InputIf]
			stats.InFlows++
			stats.InBytes += flow.Bytes
			// Collect source IPs (the network behind this input interface)
			if flow.SrcAddr != nil && !flow.SrcAddr.IsUnspecified() {
				if isPrivateIP(flow.SrcAddr) {
					if flow.SrcAddr.To4() != nil {
						stats.PrivateIPs[flow.SrcAddr.String()] = true
					} else {
						stats.PrivateIPv6s[flow.SrcAddr.String()] = true
					}
				} else {
					if flow.SrcAddr.To4() != nil {
						stats.PublicIPs[flow.SrcAddr.String()] = true
					} else {
						stats.PublicIPv6s[flow.SrcAddr.String()] = true
					}
				}
			}
		}
		// Output interface - traffic going OUT, so DstAddr is "behind" this interface
		if flow.OutputIf > 0 {
			if _, ok := t.interfaceStats[flow.OutputIf]; !ok {
				t.interfaceStats[flow.OutputIf] = &InterfaceStats{
					ID:           flow.OutputIf,
					PrivateIPs:   make(map[string]bool),
					PrivateIPv6s: make(map[string]bool),
					PublicIPs:    make(map[string]bool),
					PublicIPv6s:  make(map[string]bool),
				}
			}
			stats := t.interfaceStats[flow.OutputIf]
			stats.OutFlows++
			stats.OutBytes += flow.Bytes
			// Collect dest IPs (the network behind this output interface)
			if flow.DstAddr != nil && !flow.DstAddr.IsUnspecified() {
				if isPrivateIP(flow.DstAddr) {
					if flow.DstAddr.To4() != nil {
						stats.PrivateIPs[flow.DstAddr.String()] = true
					} else {
						stats.PrivateIPv6s[flow.DstAddr.String()] = true
					}
				} else {
					if flow.DstAddr.To4() != nil {
						stats.PublicIPs[flow.DstAddr.String()] = true
					} else {
						stats.PublicIPv6s[flow.DstAddr.String()] = true
					}
				}
			}
		}
	}

	t.lastInterfaceUpdate = time.Now()
}

// getInterfaceStats returns sorted interface statistics
func (t *TUI) getInterfaceStats() []InterfaceStats {
	// Convert to slice
	var stats []InterfaceStats
	for _, s := range t.interfaceStats {
		stats = append(stats, *s)
	}

	// Sort by total flows descending
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			totalI := stats[i].InFlows + stats[i].OutFlows
			totalJ := stats[j].InFlows + stats[j].OutFlows
			if totalJ > totalI {
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	return stats
}

// updateInterfaceTable updates the interface statistics table
func (t *TUI) updateInterfaceTable() {
	// Update subnet calculations and detect changes
	for id, stats := range t.interfaceStats {
		// IPv4 subnet
		newSubnet := guessSubnetV4(stats.PrivateIPs)
		if stats.LastSubnet != "" && stats.LastSubnet != newSubnet {
			stats.SubnetChanged = time.Now()
		}
		stats.LastSubnet = newSubnet

		// IPv6 subnet
		newSubnetV6 := guessSubnetV6(stats.PrivateIPv6s)
		if stats.LastSubnetV6 != "" && stats.LastSubnetV6 != newSubnetV6 {
			stats.SubnetV6Changed = time.Now()
		}
		stats.LastSubnetV6 = newSubnetV6

		t.interfaceStats[id] = stats
	}

	sortedStats := t.getInterfaceStats()

	// Clear existing rows (keep header)
	rowCount := t.interfaceTable.GetRowCount()
	for i := rowCount - 1; i > 0; i-- {
		t.interfaceTable.RemoveRow(i)
	}

	// Add rows - two lines per interface if IPv6 is present
	row := 1
	for _, s := range sortedStats {
		totalFlows := s.InFlows + s.OutFlows
		intIPv4Count := len(s.PrivateIPs)
		intIPv6Count := len(s.PrivateIPv6s)
		extIPv4Count := len(s.PublicIPs)
		extIPv6Count := len(s.PublicIPv6s)
		hasIPv6 := intIPv6Count > 0 || extIPv6Count > 0

		// Determine subnet colors - yellow for 5 seconds after change
		subnetColor := tcell.ColorLightCyan
		if !s.SubnetChanged.IsZero() && time.Since(s.SubnetChanged) < 5*time.Second {
			subnetColor = tcell.ColorYellow
		}
		subnetV6Color := tcell.ColorLightCyan
		if !s.SubnetV6Changed.IsZero() && time.Since(s.SubnetV6Changed) < 5*time.Second {
			subnetV6Color = tcell.ColorYellow
		}

		// Show marker if selected
		marker := ""
		if t.selectedInterfaces[s.ID] {
			marker = "*"
		}

		// IPv4 subnet display (or "-" if none)
		subnetV4 := s.LastSubnet
		if subnetV4 == "" {
			subnetV4 = "-"
		}

		// Row 1: Interface ID + IPv4 data + flow stats
		t.interfaceTable.SetCell(row, 0, tview.NewTableCell(marker).SetTextColor(tcell.ColorGreen).SetExpansion(0))
		t.interfaceTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d", s.ID)).SetExpansion(1))
		t.interfaceTable.SetCell(row, 2, tview.NewTableCell(subnetV4).SetTextColor(subnetColor).SetExpansion(1))
		t.interfaceTable.SetCell(row, 3, tview.NewTableCell(formatNumber(intIPv4Count)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 4, tview.NewTableCell(formatNumber(extIPv4Count)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 5, tview.NewTableCell(formatNumber(s.InFlows)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 6, tview.NewTableCell(formatNumber(s.OutFlows)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 7, tview.NewTableCell(formatNumber(totalFlows)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 8, tview.NewTableCell(formatBytes(s.InBytes)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 9, tview.NewTableCell(formatBytes(s.OutBytes)).SetAlign(tview.AlignRight).SetExpansion(1))
		row++

		// Row 2: IPv6 data (only if IPv6 addresses exist)
		if hasIPv6 {
			t.interfaceTable.SetCell(row, 0, tview.NewTableCell("").SetExpansion(0))
			t.interfaceTable.SetCell(row, 1, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 2, tview.NewTableCell(s.LastSubnetV6).SetTextColor(subnetV6Color).SetExpansion(1))
			t.interfaceTable.SetCell(row, 3, tview.NewTableCell(formatNumber(intIPv6Count)).SetAlign(tview.AlignRight).SetExpansion(1))
			t.interfaceTable.SetCell(row, 4, tview.NewTableCell(formatNumber(extIPv6Count)).SetAlign(tview.AlignRight).SetExpansion(1))
			// Leave flow/byte columns empty for IPv6 row
			t.interfaceTable.SetCell(row, 5, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 6, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 7, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 8, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 9, tview.NewTableCell("").SetExpansion(1))
			row++
		}
	}
}

// getInterfaceIDFromRow returns the interface ID from a table row
// If on an IPv6 continuation row (empty interface column), looks up to find the interface
func (t *TUI) getInterfaceIDFromRow(row int) uint16 {
	if row <= 0 {
		return 0
	}
	// Column 1 contains the interface ID (column 0 is the marker)
	cell := t.interfaceTable.GetCell(row, 1)
	if cell == nil {
		return 0
	}
	// If this is an IPv6 continuation row (empty interface), look at the row above
	if cell.Text == "" && row > 1 {
		cell = t.interfaceTable.GetCell(row-1, 1)
		if cell == nil {
			return 0
		}
	}
	var id uint16
	fmt.Sscanf(cell.Text, "%d", &id)
	return id
}

// applyInterfaceFilter switches to flows page with filter for selected interfaces
func (t *TUI) applyInterfaceFilter() {
	if len(t.selectedInterfaces) == 0 {
		return
	}

	// Build filter string: if=1 || if=5 || if=10
	var parts []string
	for id := range t.selectedInterfaces {
		parts = append(parts, fmt.Sprintf("if=%d", id))
	}

	filterStr := strings.Join(parts, " || ")
	t.filter = store.ParseFilter(filterStr)
	t.filterInput.SetText(filterStr)

	// Clear selections after applying
	t.selectedInterfaces = make(map[uint16]bool)

	// Switch to flows page
	t.currentPage = 0
	t.pages.SwitchToPage("flows")
	t.app.SetFocus(t.filterInput)
}

// showInterfaceDetail shows a modal with all IPs seen on an interface
func (t *TUI) showInterfaceDetail(ifaceID uint16) {
	stats, ok := t.interfaceStats[ifaceID]
	if !ok {
		return
	}

	// Check if there are any IPs
	if len(stats.PrivateIPs) == 0 && len(stats.PrivateIPv6s) == 0 {
		return
	}

	// Store state for live updates
	t.ipDetailIfaceID = ifaceID
	t.ipDetailSelected = make(map[string]bool)
	t.ipDetailVisible = true

	// Create table for IPs
	t.ipDetailTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false)

	// Initial populate
	t.updateIPDetailTable()

	// Center the modal with flexible size
	flex := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(t.ipDetailTable, 0, 2, true).
			AddItem(nil, 0, 1, false), 70, 0, true).
		AddItem(nil, 0, 1, false)

	// Handle keys
	t.ipDetailTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			t.closeIPDetail()
			return nil
		case tcell.KeyEnter:
			t.applyIPDetailFilter()
			return nil
		case tcell.KeyRune:
			if event.Rune() == ' ' {
				t.toggleIPDetailSelection()
				return nil
			}
		}
		return event
	})

	t.pages.AddPage("interface-detail", flex, true, true)
	t.app.SetFocus(t.ipDetailTable)
}

// updateIPDetailTable refreshes the IP detail table with current data
func (t *TUI) updateIPDetailTable() {
	if !t.ipDetailVisible || t.ipDetailTable == nil {
		return
	}

	stats, ok := t.interfaceStats[t.ipDetailIfaceID]
	if !ok {
		return
	}

	// Collect all IPs with type info
	type ipEntry struct {
		ip        string
		isPrivate bool
	}
	var allEntries []ipEntry
	for ip := range stats.PrivateIPs {
		allEntries = append(allEntries, ipEntry{ip, true})
	}
	for ip := range stats.PrivateIPv6s {
		allEntries = append(allEntries, ipEntry{ip, true})
	}
	for ip := range stats.PublicIPs {
		allEntries = append(allEntries, ipEntry{ip, false})
	}
	for ip := range stats.PublicIPv6s {
		allEntries = append(allEntries, ipEntry{ip, false})
	}

	// Sort: private first, then public, each sorted by range
	var privateIPs, publicIPs []string
	for _, e := range allEntries {
		if e.isPrivate {
			privateIPs = append(privateIPs, e.ip)
		} else {
			publicIPs = append(publicIPs, e.ip)
		}
	}
	sortIPsByRange(privateIPs)
	sortIPsByRange(publicIPs)

	// Rebuild sorted entries: private first, then public
	allEntries = nil
	for _, ip := range privateIPs {
		allEntries = append(allEntries, ipEntry{ip, true})
	}
	for _, ip := range publicIPs {
		allEntries = append(allEntries, ipEntry{ip, false})
	}

	// Remember selection position
	selectedRow, _ := t.ipDetailTable.GetSelection()

	// Update table
	t.ipDetailTable.Clear()
	intCount := len(privateIPs)
	extCount := len(publicIPs)
	t.ipDetailTable.SetBorder(true).SetTitle(fmt.Sprintf(" Interface %d - %d Int / %d Ext [Space=Mark] [Enter=Filter] [Esc=Close] ", t.ipDetailIfaceID, intCount, extCount))

	// Header row
	t.ipDetailTable.SetCell(0, 0, tview.NewTableCell(" ").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	t.ipDetailTable.SetCell(0, 1, tview.NewTableCell("Type").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	t.ipDetailTable.SetCell(0, 2, tview.NewTableCell("IP Address").SetTextColor(tcell.ColorYellow).SetSelectable(false).SetExpansion(1))
	t.ipDetailTable.SetCell(0, 3, tview.NewTableCell("Hostname").SetTextColor(tcell.ColorYellow).SetSelectable(false).SetExpansion(2))

	for i, entry := range allEntries {
		row := i + 1 // +1 for header
		marker := " "
		if t.ipDetailSelected[entry.ip] {
			marker = "*"
		}

		// Type indicator
		typeStr := "ext"
		typeColor := tcell.ColorOrange
		if entry.isPrivate {
			typeStr = "int"
			typeColor = tcell.ColorGreen
		}

		// DNS lookup - always try to resolve for IP detail view
		hostname := ""
		if parsedIP := net.ParseIP(entry.ip); parsedIP != nil {
			// First check cache
			if cached, ok := t.resolver.GetCached(parsedIP); ok {
				hostname = cached
			} else {
				// No cache - trigger async lookup for next refresh
				wasEnabled := t.resolver.IsEnabled()
				if !wasEnabled {
					t.resolver.SetEnabled(true)
				}
				t.resolver.Resolve(parsedIP)
				if !wasEnabled {
					t.resolver.SetEnabled(false)
				}
				hostname = "[...]" // Indicate lookup in progress
			}
		}

		t.ipDetailTable.SetCell(row, 0, tview.NewTableCell(marker).SetTextColor(tcell.ColorGreen))
		t.ipDetailTable.SetCell(row, 1, tview.NewTableCell(typeStr).SetTextColor(typeColor))
		t.ipDetailTable.SetCell(row, 2, tview.NewTableCell(entry.ip).SetExpansion(1))
		t.ipDetailTable.SetCell(row, 3, tview.NewTableCell(hostname).SetTextColor(tcell.ColorAqua).SetExpansion(2))
	}

	// Fix selection to skip header
	t.ipDetailTable.SetFixed(1, 0)

	// Restore selection if valid (account for header row)
	if selectedRow >= 1 && selectedRow <= len(allEntries) {
		t.ipDetailTable.Select(selectedRow, 0)
	} else if len(allEntries) > 0 {
		t.ipDetailTable.Select(1, 0) // Select first data row
	}
}

// toggleIPDetailSelection toggles selection of current IP
func (t *TUI) toggleIPDetailSelection() {
	if !t.ipDetailVisible || t.ipDetailTable == nil {
		return
	}

	stats, ok := t.interfaceStats[t.ipDetailIfaceID]
	if !ok {
		return
	}

	// Get all IPs (private first, then public)
	allIPs := t.getAllInterfaceIPs(stats)

	row, _ := t.ipDetailTable.GetSelection()
	// Account for header row (row 0 is header, data starts at row 1)
	dataIndex := row - 1
	if dataIndex >= 0 && dataIndex < len(allIPs) {
		ip := allIPs[dataIndex]
		if t.ipDetailSelected[ip] {
			delete(t.ipDetailSelected, ip)
		} else {
			t.ipDetailSelected[ip] = true
		}
		t.updateIPDetailTable()
	}
}

// getAllInterfaceIPs returns all IPs for an interface (private first, then public)
func (t *TUI) getAllInterfaceIPs(stats *InterfaceStats) []string {
	var privateIPs, publicIPs []string
	for ip := range stats.PrivateIPs {
		privateIPs = append(privateIPs, ip)
	}
	for ip := range stats.PrivateIPv6s {
		privateIPs = append(privateIPs, ip)
	}
	for ip := range stats.PublicIPs {
		publicIPs = append(publicIPs, ip)
	}
	for ip := range stats.PublicIPv6s {
		publicIPs = append(publicIPs, ip)
	}
	sortIPsByRange(privateIPs)
	sortIPsByRange(publicIPs)
	return append(privateIPs, publicIPs...)
}

// applyIPDetailFilter applies filter from selected IPs
func (t *TUI) applyIPDetailFilter() {
	if !t.ipDetailVisible {
		return
	}

	stats, ok := t.interfaceStats[t.ipDetailIfaceID]
	if !ok {
		return
	}

	// Get all IPs (private first, then public)
	allIPs := t.getAllInterfaceIPs(stats)

	var ipsToFilter []string
	if len(t.ipDetailSelected) > 0 {
		for ip := range t.ipDetailSelected {
			ipsToFilter = append(ipsToFilter, ip)
		}
	} else {
		// Use current row (account for header row)
		row, _ := t.ipDetailTable.GetSelection()
		dataIndex := row - 1
		if dataIndex >= 0 && dataIndex < len(allIPs) {
			ipsToFilter = append(ipsToFilter, allIPs[dataIndex])
		}
	}

	if len(ipsToFilter) > 0 {
		var parts []string
		for _, ip := range ipsToFilter {
			parts = append(parts, fmt.Sprintf("ip=%s", ip))
		}
		filterStr := strings.Join(parts, " || ")
		t.filter = store.ParseFilter(filterStr)
		t.filterInput.SetText(filterStr)

		t.closeIPDetail()
		t.currentPage = 0
		t.pages.SwitchToPage("flows")
		t.app.SetFocus(t.filterInput)
	}
}

// closeIPDetail closes the IP detail modal
func (t *TUI) closeIPDetail() {
	t.ipDetailVisible = false
	t.ipDetailTable = nil
	t.ipDetailSelected = nil
	t.pages.RemovePage("interface-detail")
	t.app.SetFocus(t.interfaceTable)
}
