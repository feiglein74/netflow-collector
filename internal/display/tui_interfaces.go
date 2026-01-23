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

// InterfaceDirection indicates whether interface is used for input or output
type InterfaceDirection int

const (
	DirectionIn  InterfaceDirection = 0
	DirectionOut InterfaceDirection = 1
)

// InterfaceKey uniquely identifies an interface entry (ID + direction)
type InterfaceKey struct {
	ID        uint16
	Direction InterfaceDirection
}

// InterfaceStats holds statistics for a single interface in one direction
type InterfaceStats struct {
	ID              uint16
	Direction       InterfaceDirection
	Flows           int
	Bytes           uint64
	Packets         uint64
	PrivateIPs      map[string]bool // Set of private IPv4s seen on this interface
	PrivateIPv6s    map[string]bool // Set of private/ULA IPv6s seen on this interface
	PublicIPs       map[string]bool // Set of public IPv4s seen on this interface
	PublicIPv6s     map[string]bool // Set of public IPv6s seen on this interface
	BytesToPublic   uint64          // Bytes sent to public destinations (for WAN detection)
	FlowsToPublic   int             // Flows to public destinations
	LastSubnet      string          // Last calculated IPv4 subnet
	LastSubnetV6    string          // Last calculated IPv6 subnet
	SubnetChanged   time.Time       // When IPv4 subnet last changed
	SubnetV6Changed time.Time       // When IPv6 subnet last changed
}

// setupInterfaceTableHeaders sets up the interface table headers
func (t *TUI) setupInterfaceTableHeaders() {
	headers := []string{"*", "Interface", "Dir", "Subnet (guessed)", "Int", "Ext", "Flows", "Bytes", "Packets"}
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
			key := InterfaceKey{ID: flow.InputIf, Direction: DirectionIn}
			if _, ok := t.interfaceStats[key]; !ok {
				t.interfaceStats[key] = &InterfaceStats{
					ID:           flow.InputIf,
					Direction:    DirectionIn,
					PrivateIPs:   make(map[string]bool),
					PrivateIPv6s: make(map[string]bool),
					PublicIPs:    make(map[string]bool),
					PublicIPv6s:  make(map[string]bool),
				}
			}
			stats := t.interfaceStats[key]
			stats.Flows++
			stats.Bytes += flow.Bytes
			stats.Packets += uint64(flow.Packets)
			// Collect source IPs (the network behind this input interface)
			if flow.SrcAddr != nil && !flow.SrcAddr.IsUnspecified() {
				// Learn IPv6 prefixes only from ROUTED flows (InIf + OutIf)
				// These are flows from internal devices going to the internet
				if flow.OutputIf > 0 {
					t.learnIPv6Prefix(flow.SrcAddr)
				}

				// Classify using isInternalIP (private IPs + our own IPv6 prefix)
				if t.isInternalIP(flow.SrcAddr) {
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
			key := InterfaceKey{ID: flow.OutputIf, Direction: DirectionOut}
			if _, ok := t.interfaceStats[key]; !ok {
				t.interfaceStats[key] = &InterfaceStats{
					ID:           flow.OutputIf,
					Direction:    DirectionOut,
					PrivateIPs:   make(map[string]bool),
					PrivateIPv6s: make(map[string]bool),
					PublicIPs:    make(map[string]bool),
					PublicIPv6s:  make(map[string]bool),
				}
			}
			stats := t.interfaceStats[key]
			stats.Flows++
			stats.Bytes += flow.Bytes
			stats.Packets += uint64(flow.Packets)
			// Collect dest IPs (the network behind this output interface)
			if flow.DstAddr != nil && !flow.DstAddr.IsUnspecified() {
				// Use isInternalIP which includes learned prefixes
				if t.isInternalIP(flow.DstAddr) {
					if flow.DstAddr.To4() != nil {
						stats.PrivateIPs[flow.DstAddr.String()] = true
					} else {
						stats.PrivateIPv6s[flow.DstAddr.String()] = true
					}
				} else {
					// Track traffic to public destinations (for WAN detection)
					stats.BytesToPublic += flow.Bytes
					stats.FlowsToPublic++
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
// Sorted by: Interface ID ascending, then Direction (In before Out)
func (t *TUI) getInterfaceStats() []InterfaceStats {
	// Convert to slice
	var stats []InterfaceStats
	for _, s := range t.interfaceStats {
		stats = append(stats, *s)
	}

	// Sort by Interface ID, then Direction (In=0 before Out=1)
	for i := 0; i < len(stats); i++ {
		for j := i + 1; j < len(stats); j++ {
			// Compare by ID first
			if stats[j].ID < stats[i].ID {
				stats[i], stats[j] = stats[j], stats[i]
			} else if stats[j].ID == stats[i].ID && stats[j].Direction < stats[i].Direction {
				// Same ID, sort by direction (In=0 before Out=1)
				stats[i], stats[j] = stats[j], stats[i]
			}
		}
	}

	return stats
}

// GuessWANInterface returns the interface ID that is most likely the WAN/public interface
// Detection: Interface (any direction) with the most unique public IPs seen
// This works because WAN sees ALL public IPs the network communicates with
func (t *TUI) GuessWANInterface() (uint16, int) {
	// Aggregate public IP counts per interface ID (combine In + Out directions)
	ifacePublicIPs := make(map[uint16]map[string]bool)

	for key, stats := range t.interfaceStats {
		if ifacePublicIPs[key.ID] == nil {
			ifacePublicIPs[key.ID] = make(map[string]bool)
		}
		// Collect all public IPs seen on this interface
		for ip := range stats.PublicIPs {
			ifacePublicIPs[key.ID][ip] = true
		}
		for ip := range stats.PublicIPv6s {
			ifacePublicIPs[key.ID][ip] = true
		}
	}

	// Find interface with most unique public IPs
	var wanID uint16
	var maxPublicIPs int

	for ifaceID, publicIPs := range ifacePublicIPs {
		count := len(publicIPs)
		if count > maxPublicIPs {
			maxPublicIPs = count
			wanID = ifaceID
		}
	}

	return wanID, maxPublicIPs
}

// updateInterfaceTable updates the interface statistics table
func (t *TUI) updateInterfaceTable() {
	// Update subnet calculations and detect changes
	for key, stats := range t.interfaceStats {
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

		t.interfaceStats[key] = stats
	}

	sortedStats := t.getInterfaceStats()

	// Guess WAN interface (by most unique public IPs)
	wanID, wanPublicCount := t.GuessWANInterface()

	// Clear existing rows (keep header)
	rowCount := t.interfaceTable.GetRowCount()
	for i := rowCount - 1; i > 0; i-- {
		t.interfaceTable.RemoveRow(i)
	}

	// Add rows - one per interface+direction, with optional IPv6 continuation row
	row := 1
	for _, s := range sortedStats {
		// Check if this is the guessed WAN interface (mark both In and Out for this interface)
		isWAN := s.ID == wanID && wanPublicCount > 0
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

		// Show marker if selected or WAN
		key := InterfaceKey{ID: s.ID, Direction: s.Direction}
		marker := ""
		markerColor := tcell.ColorGreen
		if t.selectedInterfaces[key] {
			marker = "*"
		}
		if isWAN {
			marker = "WAN"
			markerColor = tcell.ColorYellow
		}

		// Direction display
		dirStr := "In"
		dirColor := tcell.ColorGreen
		if s.Direction == DirectionOut {
			dirStr = "Out"
			dirColor = tcell.ColorOrange
		}
		// Mark WAN interface in yellow
		if isWAN {
			dirColor = tcell.ColorYellow
		}

		// IPv4 subnet display (or "-" if none)
		subnetV4 := s.LastSubnet
		if subnetV4 == "" {
			subnetV4 = "-"
		}

		// Row 1: Interface ID + Direction + IPv4 data + flow stats
		// Columns: *, Interface, Dir, Subnet (guessed), Int, Ext, Flows, Bytes, Packets
		t.interfaceTable.SetCell(row, 0, tview.NewTableCell(marker).SetTextColor(markerColor).SetExpansion(0))
		t.interfaceTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d", s.ID)).SetExpansion(1))
		t.interfaceTable.SetCell(row, 2, tview.NewTableCell(dirStr).SetTextColor(dirColor).SetExpansion(1))
		t.interfaceTable.SetCell(row, 3, tview.NewTableCell(subnetV4).SetTextColor(subnetColor).SetExpansion(1))
		t.interfaceTable.SetCell(row, 4, tview.NewTableCell(formatNumber(intIPv4Count)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 5, tview.NewTableCell(formatNumber(extIPv4Count)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 6, tview.NewTableCell(formatNumber(s.Flows)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 7, tview.NewTableCell(formatBytes(s.Bytes)).SetAlign(tview.AlignRight).SetExpansion(1))
		t.interfaceTable.SetCell(row, 8, tview.NewTableCell(formatNumber(int(s.Packets))).SetAlign(tview.AlignRight).SetExpansion(1))
		row++

		// Row 2: IPv6 data (only if IPv6 addresses exist)
		if hasIPv6 {
			t.interfaceTable.SetCell(row, 0, tview.NewTableCell("").SetExpansion(0))
			t.interfaceTable.SetCell(row, 1, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 2, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 3, tview.NewTableCell(s.LastSubnetV6).SetTextColor(subnetV6Color).SetExpansion(1))
			t.interfaceTable.SetCell(row, 4, tview.NewTableCell(formatNumber(intIPv6Count)).SetAlign(tview.AlignRight).SetExpansion(1))
			t.interfaceTable.SetCell(row, 5, tview.NewTableCell(formatNumber(extIPv6Count)).SetAlign(tview.AlignRight).SetExpansion(1))
			// Leave flow/byte/packet columns empty for IPv6 row
			t.interfaceTable.SetCell(row, 6, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 7, tview.NewTableCell("").SetExpansion(1))
			t.interfaceTable.SetCell(row, 8, tview.NewTableCell("").SetExpansion(1))
			row++
		}
	}
}

// getInterfaceKeyFromRow returns the InterfaceKey (ID + Direction) from a table row
// If on an IPv6 continuation row (empty interface column), looks up to find the interface
func (t *TUI) getInterfaceKeyFromRow(row int) (InterfaceKey, bool) {
	if row <= 0 {
		return InterfaceKey{}, false
	}

	// Column 1 contains the interface ID, column 2 contains direction
	idCell := t.interfaceTable.GetCell(row, 1)
	dirCell := t.interfaceTable.GetCell(row, 2)
	if idCell == nil {
		return InterfaceKey{}, false
	}

	// If this is an IPv6 continuation row (empty interface), look at the row above
	if idCell.Text == "" && row > 1 {
		idCell = t.interfaceTable.GetCell(row-1, 1)
		dirCell = t.interfaceTable.GetCell(row-1, 2)
		if idCell == nil {
			return InterfaceKey{}, false
		}
	}

	var id uint16
	fmt.Sscanf(idCell.Text, "%d", &id)
	if id == 0 {
		return InterfaceKey{}, false
	}

	// Parse direction
	dir := DirectionIn
	if dirCell != nil && dirCell.Text == "Out" {
		dir = DirectionOut
	}

	return InterfaceKey{ID: id, Direction: dir}, true
}

// applyInterfaceFilter switches to flows page with filter for selected interfaces
func (t *TUI) applyInterfaceFilter() {
	if len(t.selectedInterfaces) == 0 {
		return
	}

	// Build filter string: inif=1 || outif=5 (direction-specific)
	var parts []string
	for key := range t.selectedInterfaces {
		if key.Direction == DirectionIn {
			parts = append(parts, fmt.Sprintf("inif=%d", key.ID))
		} else {
			parts = append(parts, fmt.Sprintf("outif=%d", key.ID))
		}
	}

	filterStr := strings.Join(parts, " || ")
	t.filter = store.ParseFilter(filterStr)
	t.filterInput.SetText(filterStr)

	// Clear selections after applying
	t.selectedInterfaces = make(map[InterfaceKey]bool)

	// Switch to flows page
	t.currentPage = 0
	t.pages.SwitchToPage("flows")
	t.app.SetFocus(t.filterInput)
}

// showInterfaceDetail shows a modal with all IPs seen on an interface
func (t *TUI) showInterfaceDetail(key InterfaceKey) {
	stats, ok := t.interfaceStats[key]
	if !ok {
		return
	}

	// Check if there are any IPs
	if len(stats.PrivateIPs) == 0 && len(stats.PrivateIPv6s) == 0 && len(stats.PublicIPs) == 0 && len(stats.PublicIPv6s) == 0 {
		return
	}

	// Store state for live updates
	t.ipDetailIfaceKey = key
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

	stats, ok := t.interfaceStats[t.ipDetailIfaceKey]
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
	dirStr := "In"
	if t.ipDetailIfaceKey.Direction == DirectionOut {
		dirStr = "Out"
	}
	t.ipDetailTable.SetBorder(true).SetTitle(fmt.Sprintf(" Interface %d (%s) - %d Int / %d Ext [Space=Mark] [Enter=Filter] [Esc=Close] ", t.ipDetailIfaceKey.ID, dirStr, intCount, extCount))

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

	stats, ok := t.interfaceStats[t.ipDetailIfaceKey]
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

	stats, ok := t.interfaceStats[t.ipDetailIfaceKey]
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
