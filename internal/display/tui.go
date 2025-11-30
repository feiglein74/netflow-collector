package display

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/resolver"
	"netflow-collector/internal/store"
	"netflow-collector/pkg/types"
)

const historyFile = ".netflow-filter-history"

// getHistoryPath returns the path to the history file
func getHistoryPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, historyFile)
	}
	return historyFile
}

// loadFilterHistory loads filter history from file
func loadFilterHistory() []string {
	path := getHistoryPath()
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var history []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			history = append(history, line)
		}
	}
	return history
}

// saveFilterHistory saves filter history to file
func saveFilterHistory(history []string) {
	path := getHistoryPath()
	file, err := os.Create(path)
	if err != nil {
		return
	}
	defer file.Close()

	for _, filter := range history {
		fmt.Fprintln(file, filter)
	}
}

// TUI represents the interactive terminal UI
type TUI struct {
	app         *tview.Application
	store       *store.FlowStore
	resolver    *resolver.Resolver
	table       *tview.Table
	statsView   *tview.TextView
	filterView  *tview.TextView
	helpView    *tview.TextView
	detailView  *tview.TextView
	filterInput *tview.InputField
	layout      *tview.Flex
	pages       *tview.Pages // For overlay dropdown and page switching

	// Interface statistics page
	interfaceTable       *tview.Table
	interfaceLayout      *tview.Flex
	currentPage          int                        // 0 = flows, 1 = interfaces
	interfaceStats       map[uint16]*InterfaceStats // Cumulative interface statistics
	lastInterfaceUpdate  time.Time                  // Track when we last updated stats
	selectedInterfaces   map[uint16]bool            // Interfaces marked with Space for filtering

	// IP detail modal state
	ipDetailTable     *tview.Table
	ipDetailIfaceID   uint16
	ipDetailSelected  map[string]bool
	ipDetailVisible   bool

	// Autocomplete dropdown overlay
	dropdown        *tview.List
	suggestions     []string
	dropdownVisible bool

	// State
	filter       store.Filter
	sortField    store.SortField
	sortAsc      bool
	paused       bool
	showHelp     bool
	showDetail   bool
	showVersion  bool // Version column hidden by default
	showDNS      bool // Show hostnames instead of IPs
	showService  bool // Show service names for ports
	filterActive bool // Is filter input focused
	refreshRate  time.Duration
	stopChan     chan struct{}

	// Column width tracking (high water mark - only grows, never shrinks)
	colWidths []int
	lastWidth int // Track terminal width to detect shrinking

	// Filter history
	filterHistory []string
	historyIndex  int // -1 = new input, 0+ = browsing history

	// Current displayed flows (for detail view)
	currentFlows []types.Flow
}

// NewTUI creates a new interactive TUI
func NewTUI(s *store.FlowStore, refreshRate time.Duration) *TUI {
	if refreshRate == 0 {
		refreshRate = 500 * time.Millisecond
	}

	t := &TUI{
		app:            tview.NewApplication(),
		store:          s,
		resolver:       resolver.New(),
		sortField:      store.SortByTime,
		sortAsc:        false,
		showService:    true, // Enable service names by default
		refreshRate:    refreshRate,
		stopChan:       make(chan struct{}),
		filterHistory:  loadFilterHistory(),
		interfaceStats:     make(map[uint16]*InterfaceStats),
		selectedInterfaces: make(map[uint16]bool),
	}

	t.setupUI()
	return t
}

func (t *TUI) setupUI() {
	// Stats view at top
	t.statsView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	t.statsView.SetBorder(true).SetTitle(" Statistics ")

	// Filter status view
	t.filterView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	t.filterView.SetBorder(true).SetTitle(" Filter & Sort ")

	// Main flow table
	t.table = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	t.table.SetBorder(true).SetTitle(" Flows [F2=Interfaces] ")

	// Interface statistics table
	t.interfaceTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	t.interfaceTable.SetBorder(true).SetTitle(" Interfaces [F1=Flows] [Space=Mark] [Enter=Filter] ")
	t.setupInterfaceTableHeaders()

	// Interface table key handling
	t.interfaceTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyRune:
			if event.Rune() == ' ' {
				// Toggle selection of current interface
				row, _ := t.interfaceTable.GetSelection()
				if row > 0 { // Skip header
					ifaceID := t.getInterfaceIDFromRow(row)
					if ifaceID > 0 {
						if t.selectedInterfaces[ifaceID] {
							delete(t.selectedInterfaces, ifaceID)
						} else {
							t.selectedInterfaces[ifaceID] = true
						}
						t.updateInterfaceTable()
					}
				}
				return nil
			}
		case tcell.KeyEnter:
			if len(t.selectedInterfaces) > 0 {
				// Switch to flows page with filter for selected interfaces
				t.applyInterfaceFilter()
				return nil
			} else {
				// Show IP detail view for current interface
				row, _ := t.interfaceTable.GetSelection()
				ifaceID := t.getInterfaceIDFromRow(row)
				if ifaceID > 0 {
					t.showInterfaceDetail(ifaceID)
					return nil
				}
			}
		}
		return event
	})

	// Filter input (no tview autocomplete - we use our own overlay)
	t.filterInput = tview.NewInputField().
		SetLabel("Filter: ").
		SetFieldWidth(0)

	// Dropdown overlay list
	t.dropdown = tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorDarkCyan).
		SetSelectedTextColor(tcell.ColorWhite).
		SetMainTextColor(tcell.ColorYellow)
	t.dropdown.SetBorder(true).SetTitle(" ↑↓ Navigate, Tab/Enter Select, Esc Close ")
	t.dropdown.SetBackgroundColor(tcell.ColorBlack)

	// Filter input key handling
	t.filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyUp:
			if t.dropdownVisible && t.dropdown.GetItemCount() > 0 {
				idx := t.dropdown.GetCurrentItem()
				if idx > 0 {
					t.dropdown.SetCurrentItem(idx - 1)
				} else {
					t.dropdown.SetCurrentItem(t.dropdown.GetItemCount() - 1)
				}
				return nil
			}
		case tcell.KeyDown:
			if t.dropdownVisible && t.dropdown.GetItemCount() > 0 {
				idx := t.dropdown.GetCurrentItem()
				if idx < t.dropdown.GetItemCount()-1 {
					t.dropdown.SetCurrentItem(idx + 1)
				} else {
					t.dropdown.SetCurrentItem(0)
				}
				return nil
			}
		case tcell.KeyTab:
			// Tab only selects from dropdown, doesn't apply filter
			if t.dropdownVisible && t.dropdown.GetItemCount() > 0 {
				idx := t.dropdown.GetCurrentItem()
				if idx >= 0 && idx < len(t.suggestions) {
					t.filterInput.SetText(t.suggestions[idx])
				}
				t.hideDropdown()
				return nil
			}
		case tcell.KeyEnter:
			// Enter applies the filter (and selects from dropdown if visible)
			if t.dropdownVisible && t.dropdown.GetItemCount() > 0 {
				idx := t.dropdown.GetCurrentItem()
				if idx >= 0 && idx < len(t.suggestions) {
					t.filterInput.SetText(t.suggestions[idx])
				}
				t.hideDropdown()
			}
			// Apply the filter
			t.applyFilterFromInput()
			return nil
		case tcell.KeyEscape:
			if t.dropdownVisible {
				t.hideDropdown()
				return nil
			}
		}
		return event
	})

	// Update dropdown when text changes
	t.filterInput.SetChangedFunc(func(text string) {
		t.updateDropdown(text)
	})

	// Help view
	t.helpView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	t.helpView.SetText(t.getHelpText())
	t.helpView.SetBorder(true).SetTitle(" Help (Press ? to toggle) ")

	// Detail view for selected flow
	t.detailView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	t.detailView.SetBorder(true).SetTitle(" Flow Details (Esc to close) ")

	// Filter input at top (with border for visibility)
	t.filterInput.SetBorder(true).SetTitle(" Filter (↑↓ suggestions, Enter apply) ")
	t.filterInput.SetBackgroundColor(tcell.ColorBlack)
	t.filterInput.SetFieldBackgroundColor(tcell.ColorDarkBlue)

	// Top section: stats + filter status
	topRow := tview.NewFlex().
		AddItem(t.statsView, 0, 2, false).
		AddItem(t.filterView, 0, 1, false)

	// Main layout (Flows page)
	t.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.filterInput, 3, 0, true).
		AddItem(topRow, 7, 0, false).
		AddItem(t.table, 0, 1, false)

	// Interface layout (Interfaces page)
	interfaceTopRow := tview.NewFlex().
		AddItem(t.statsView, 0, 1, false)
	t.interfaceLayout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(interfaceTopRow, 5, 0, false).
		AddItem(t.interfaceTable, 0, 1, true)

	// Pages for page switching and overlay support
	t.pages = tview.NewPages().
		AddPage("flows", t.layout, true, true).
		AddPage("interfaces", t.interfaceLayout, true, false)

	// Setup table headers
	t.setupTableHeaders()

	// Global key bindings
	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			t.app.Stop()
			return nil
		}
		// F1/F2 switch pages
		if event.Key() == tcell.KeyF1 {
			if t.currentPage != 0 {
				t.currentPage = 0
				t.pages.SwitchToPage("flows")
				t.app.SetFocus(t.filterInput)
			}
			return nil
		}
		if event.Key() == tcell.KeyF2 {
			if t.currentPage != 1 {
				t.currentPage = 1
				t.pages.SwitchToPage("interfaces")
				t.app.SetFocus(t.interfaceTable)
			}
			return nil
		}
		return event
	})

	t.app.EnableMouse(false)
	t.app.SetRoot(t.pages, true)
	t.app.SetFocus(t.filterInput)
}

// columnDef defines a table column with minimum width
type columnDef struct {
	name     string
	minWidth int
}

// getColumns returns column definitions based on current display settings
func (t *TUI) getColumns() []columnDef {
	cols := []columnDef{}
	if t.showVersion {
		cols = append(cols, columnDef{"Ver", 5})
	}

	// Column name depends on whether service names are shown
	protoCol := "Proto"
	if t.showService {
		protoCol = "Service"
	}

	cols = append(cols,
		columnDef{"Source", 18},
		columnDef{"Destination", 18},
		columnDef{protoCol, 8},
		columnDef{"Bytes", 8},
		columnDef{"Packets", 7},
		columnDef{"Flags", 6},
		columnDef{"Age", 8},
	)
	return cols
}

// getColWidth returns the current width for a column (high water mark)
func (t *TUI) getColWidth(colIndex int, content string, minWidth int) int {
	// Ensure colWidths slice is large enough
	for len(t.colWidths) <= colIndex {
		t.colWidths = append(t.colWidths, 0)
	}

	// Calculate required width
	contentLen := len(content)
	required := contentLen
	if required < minWidth {
		required = minWidth
	}

	// Update high water mark (only grows)
	if required > t.colWidths[colIndex] {
		t.colWidths[colIndex] = required
	}

	return t.colWidths[colIndex]
}

// resetColWidths resets column widths (call when version toggle changes column count)
func (t *TUI) resetColWidths() {
	t.colWidths = nil
}

func (t *TUI) setupTableHeaders() {
	t.table.Clear()

	cols := t.getColumns()
	for i, col := range cols {
		// Get current width (respects high water mark)
		width := t.getColWidth(i, col.name, col.minWidth)
		name := col.name
		if len(name) < width {
			name = name + strings.Repeat(" ", width-len(name))
		}
		cell := tview.NewTableCell(name).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false).
			SetExpansion(1)
		t.table.SetCell(0, i, cell)
	}
}

func (t *TUI) clearFilter() {
	t.filter = store.Filter{}
}

// applyFilterFromInput parses the current filter input text and applies it
func (t *TUI) applyFilterFromInput() {
	text := strings.TrimSpace(t.filterInput.GetText())
	if text == "" {
		t.filter = store.Filter{}
	} else {
		t.filter = store.ParseFilter(text)
		// Add to history if valid and not already in history
		if t.filter.IsValid() && text != "" {
			// Check if already in history
			found := false
			for _, h := range t.filterHistory {
				if h == text {
					found = true
					break
				}
			}
			if !found {
				// Add to front of history
				t.filterHistory = append([]string{text}, t.filterHistory...)
				// Keep max 20 entries
				if len(t.filterHistory) > 20 {
					t.filterHistory = t.filterHistory[:20]
				}
				saveFilterHistory(t.filterHistory)
			}
		}
	}
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
		ip     string
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
			parts = append(parts, fmt.Sprintf("host=%s", ip))
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

// closeIPDetail closes the IP detail modal
func (t *TUI) closeIPDetail() {
	t.ipDetailVisible = false
	t.ipDetailTable = nil
	t.ipDetailSelected = nil
	t.pages.RemovePage("interface-detail")
	t.app.SetFocus(t.interfaceTable)
}

// updateDropdown updates suggestions and shows/hides dropdown
func (t *TUI) updateDropdown(text string) {
	t.suggestions = t.getFilterAutocomplete(text)
	if len(t.suggestions) > 0 {
		t.showDropdown()
	} else {
		t.hideDropdown()
	}
}

// showDropdown displays the dropdown overlay
func (t *TUI) showDropdown() {
	t.dropdown.Clear()
	for _, s := range t.suggestions {
		t.dropdown.AddItem(s, "", 0, nil)
	}
	t.dropdown.SetCurrentItem(0)

	if !t.dropdownVisible {
		t.dropdownVisible = true
		// Create a modal-like overlay positioned below filter input
		// Height: number of items + 2 for border, max 10
		height := len(t.suggestions) + 2
		if height > 10 {
			height = 10
		}

		// Dropdown overlay: positioned at top, under the filter input (row 3)
		// Using a Flex to position it
		dropdownContainer := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 3, 0, false).              // Spacer for filter input height
			AddItem(t.dropdown, height, 0, false). // The dropdown
			AddItem(nil, 0, 1, false)              // Rest of space

		t.pages.AddPage("dropdown", dropdownContainer, true, true)
	} else {
		// Just update content, already visible
	}
	t.app.SetFocus(t.filterInput) // Keep focus on input
}

// hideDropdown hides the dropdown overlay
func (t *TUI) hideDropdown() {
	if t.dropdownVisible {
		t.dropdownVisible = false
		t.pages.RemovePage("dropdown")
		t.app.SetFocus(t.filterInput)
	}
}

// getFilterAutocomplete returns autocomplete suggestions based on current input
func (t *TUI) getFilterAutocomplete(currentText string) []string {
	if currentText == "" {
		// Show field suggestions and recent history
		suggestions := []string{}
		// Add some history entries first
		for i, h := range t.filterHistory {
			if i >= 3 {
				break
			}
			suggestions = append(suggestions, h)
		}
		return suggestions
	}

	// Filter field names
	filterFields := []string{
		"src=", "dst=", "host=", "port:", "srcport:", "dstport:",
		"proto=", "protocol=", "service=", "svc=", "version=",
		"if=", "inif=", "outif=",
		"host!=", "src!=", "dst!=", "service!=", "proto!=",
	}

	// Operators
	operators := []string{" && ", " || ", "!("}

	// Protocol values
	protocols := []string{"tcp", "udp", "icmp", "gre", "esp"}

	var suggestions []string

	// Get the last "word" being typed (after space or operator)
	lastWord := currentText
	for _, sep := range []string{" ", "(", ")"} {
		if idx := strings.LastIndex(currentText, sep); idx >= 0 {
			if idx+len(sep) < len(currentText) {
				lastWord = currentText[idx+len(sep):]
			} else {
				lastWord = ""
			}
		}
	}

	// Determine context
	trimmed := strings.TrimSpace(currentText)

	// After = or : suggest values
	if strings.HasSuffix(trimmed, "proto=") || strings.HasSuffix(trimmed, "protocol=") {
		for _, p := range protocols {
			suggestions = append(suggestions, currentText+p)
		}
		return suggestions
	}

	if strings.HasSuffix(trimmed, "service=") || strings.HasSuffix(trimmed, "svc=") {
		// Get services actually seen in current flows
		seenServices := t.getSeenServices()
		for _, s := range seenServices {
			suggestions = append(suggestions, currentText+s)
		}
		return suggestions
	}

	if strings.HasSuffix(trimmed, "port:") || strings.HasSuffix(trimmed, "srcport:") || strings.HasSuffix(trimmed, "dstport:") {
		// Get ports actually seen in current flows
		seenPorts := t.getSeenPorts()
		for _, p := range seenPorts {
			suggestions = append(suggestions, currentText+p)
		}
		return suggestions
	}

	if strings.HasSuffix(trimmed, "host=") || strings.HasSuffix(trimmed, "src=") || strings.HasSuffix(trimmed, "dst=") {
		// Get IPs actually seen in current flows
		seenIPs := t.getSeenIPs()
		for _, ip := range seenIPs {
			suggestions = append(suggestions, currentText+ip)
		}
		return suggestions
	}

	if strings.HasSuffix(trimmed, "if=") || strings.HasSuffix(trimmed, "inif=") || strings.HasSuffix(trimmed, "outif=") {
		// Get interfaces actually seen in current flows
		seenInterfaces := t.getSeenInterfaces()
		for _, iface := range seenInterfaces {
			suggestions = append(suggestions, currentText+iface)
		}
		return suggestions
	}

	// After a complete condition, suggest operators
	if len(trimmed) > 0 {
		// Check if we might be at a point where an operator makes sense
		lastChar := trimmed[len(trimmed)-1]
		if lastChar != '=' && lastChar != ':' && lastChar != '(' && lastChar != '!' {
			// Could suggest operators
			for _, op := range operators {
				suggestions = append(suggestions, currentText+op)
			}
		}
	}

	// Suggest field names that match what's being typed
	lowLast := strings.ToLower(lastWord)
	if lowLast != "" {
		for _, f := range filterFields {
			if strings.HasPrefix(strings.ToLower(f), lowLast) && f != lastWord {
				// Replace the last word with the suggestion
				prefix := currentText[:len(currentText)-len(lastWord)]
				suggestions = append(suggestions, prefix+f)
			}
		}
	}

	// Match history entries
	lowText := strings.ToLower(currentText)
	for _, h := range t.filterHistory {
		if strings.HasPrefix(strings.ToLower(h), lowText) && h != currentText {
			suggestions = append(suggestions, h)
		}
	}

	// Limit suggestions
	if len(suggestions) > 8 {
		suggestions = suggestions[:8]
	}

	return suggestions
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

func (t *TUI) showFlowDetail() {
	row, _ := t.table.GetSelection()
	if row <= 0 || row > len(t.currentFlows) {
		return
	}

	flow := t.currentFlows[row-1] // -1 for header row
	t.showDetail = true

	// Mark this flow as accessed for LRU protection
	t.store.MarkFlowAccessed(flow.FlowKey())

	// Format flow details
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
	t.layout.Clear()
	t.layout.AddItem(t.detailView, 0, 1, true)
}

func (t *TUI) hideFlowDetail() {
	t.showDetail = false
	t.layout.Clear()
	topRow := tview.NewFlex().
		AddItem(t.statsView, 0, 2, false).
		AddItem(t.filterView, 0, 1, false)
	t.layout.AddItem(t.filterInput, 3, 0, true)
	t.layout.AddItem(topRow, 7, 0, false)
	t.layout.AddItem(t.table, 0, 1, false)
	t.app.SetFocus(t.filterInput)
}

func (t *TUI) setSortField(field store.SortField) {
	if t.sortField == field {
		t.sortAsc = !t.sortAsc
	} else {
		t.sortField = field
		t.sortAsc = false
	}
}

func (t *TUI) toggleHelp() {
	t.showHelp = !t.showHelp
	if t.showHelp {
		t.layout.Clear()
		t.layout.AddItem(t.helpView, 0, 1, true)
	} else {
		t.layout.Clear()
		topRow := tview.NewFlex().
			AddItem(t.statsView, 0, 2, false).
			AddItem(t.filterView, 0, 1, false)
		t.layout.AddItem(t.filterInput, 3, 0, true)
		t.layout.AddItem(topRow, 7, 0, false)
		t.layout.AddItem(t.table, 0, 1, false)
		t.app.SetFocus(t.filterInput)
	}
}

func (t *TUI) getHelpText() string {
	return `[yellow]NetFlow/IPFIX Collector - Keyboard Shortcuts[white]

[green]Navigation:[white]
  Up/Down, j/k    Scroll through flows
  PgUp/PgDn       Page up/down
  Home/End        Jump to start/end
  Enter           Show flow details

[green]Sorting:[white]
  1-6             Sort by Time/Bytes/Pkts/Src/Dst/Proto
  r               Reverse sort order (ASC/DESC)

[green]Filtering (Wireshark-style):[white]
  f or /          Open filter input
  Up/Down         Navigate autocomplete suggestions
  Tab/Enter       Accept autocomplete suggestion
  Ctrl+Up/Down    Browse filter history
  c               Clear filter

[green]Filter Syntax:[white]
  src=192.168     Source IP contains
  dst=10.0        Dest IP contains
  ip=8.8          Either src or dst
  port=443        Either port
  sport/dport     Source/dest port
  proto=tcp       Protocol

[green]Filter Operators:[white]
  && or space     AND
  ||              OR
  ! or not        NOT
  ( )             Grouping

[green]Examples:[white]
  src=192.168 proto=tcp
  port=80 || port=443
  !(src=10.0.0.1 && port=53)

[green]Display:[white]
  n               Toggle DNS resolution
  e               Toggle service names (http, ssh, etc.)
  v               Toggle version column
  Space           Pause/Resume
  ?               This help
  q               Quit

Press ? or Esc to close`
}

func (t *TUI) updateStats() {
	stats := t.store.GetStats()
	filteredStats := t.store.GetFilteredStats(&t.filter)

	pauseIndicator := ""
	if t.paused {
		pauseIndicator = " [red][PAUSED][white]"
	}

	// Build version info - highlight if multiple versions present
	versionParts := []string{}
	versionCount := 0
	if stats.V5Flows > 0 {
		versionParts = append(versionParts, fmt.Sprintf("v5:%d", stats.V5Flows))
		versionCount++
	}
	if stats.V9Flows > 0 {
		versionParts = append(versionParts, fmt.Sprintf("v9:%d", stats.V9Flows))
		versionCount++
	}
	if stats.IPFIXFlows > 0 {
		versionParts = append(versionParts, fmt.Sprintf("IPFIX:%d", stats.IPFIXFlows))
		versionCount++
	}

	versionText := "[gray]none[white]"
	if len(versionParts) > 0 {
		if versionCount > 1 {
			// Multiple versions - highlight in yellow, suggest 'v' to show column
			versionText = "[yellow]" + strings.Join(versionParts, " ") + "[white] [gray](v=show)[white]"
		} else {
			versionText = "[green]" + strings.Join(versionParts, " ") + "[white]"
		}
	}

	// Show filtered stats if filter is active
	showingText := formatNumber(filteredStats.Count)
	if !t.filter.IsEmpty() && t.filter.IsValid() {
		showingText = fmt.Sprintf("%s (%s, %s pkts)",
			formatNumber(filteredStats.Count),
			formatBytes(filteredStats.Bytes),
			formatNumber(int(filteredStats.Packets)))
	}

	// Filter error line (if any)
	filterErrorLine := ""
	if t.filter.String() != "" && !t.filter.IsValid() && t.filter.Error != "" {
		filterErrorLine = "\n[red]Filter: " + tview.Escape(t.filter.Error) + "[white]"
	}

	// Memory usage indicator
	flowCount := t.store.GetFlowCount()
	maxFlows := t.store.GetMaxFlows()
	memText := fmt.Sprintf("%s/%s", formatNumber(flowCount), formatNumber(maxFlows))
	if flowCount >= maxFlows {
		memText = "[red]" + memText + "[white]"
	} else if flowCount > maxFlows*80/100 {
		memText = "[yellow]" + memText + "[white]"
	}

	// Eviction stats - show when eviction has occurred
	evictionStats := t.store.GetEvictionStats()
	evictionText := ""
	if evictionStats.TotalEvicted > 0 {
		evictionText = fmt.Sprintf("  [yellow]Evicted:[white] %s [gray](TopK:%d LRU:%d)[white]",
			formatNumber(int(evictionStats.TotalEvicted)),
			evictionStats.TopKProtected,
			evictionStats.LRUProtected)
	}

	text := fmt.Sprintf(
		"[yellow]Flows:[white] %s  [yellow]Mem:[white] %s  [yellow]Rate:[white] %s/s  [yellow]Throughput:[white] %s/s%s%s\n"+
			"[yellow]Versions:[white] %s  [yellow]Exporters:[white] %d  [yellow]Showing:[white] %s%s",
		formatNumber(int(stats.TotalFlows)),
		memText,
		formatDecimal(stats.FlowsPerSecond, 1),
		formatBytes(uint64(stats.BytesPerSecond)),
		evictionText,
		pauseIndicator,
		versionText,
		stats.UniqueExporters,
		showingText,
		filterErrorLine,
	)
	t.statsView.SetText(text)
}

func (t *TUI) updateFilterView() {
	sortDir := "DESC"
	if t.sortAsc {
		sortDir = "ASC"
	}

	// Update filter input label with status
	if t.filter.String() != "" {
		if !t.filter.IsValid() {
			t.filterInput.SetLabel("Filter [ERR]: ")
			t.filterInput.SetLabelColor(tcell.ColorRed)
		} else {
			matchCount := t.store.GetFilteredCount(&t.filter)
			if matchCount == 0 {
				t.filterInput.SetLabel("Filter [0]: ")
				t.filterInput.SetLabelColor(tcell.ColorYellow)
			} else {
				t.filterInput.SetLabel("Filter [OK]: ")
				t.filterInput.SetLabelColor(tcell.ColorGreen)
			}
		}
	} else {
		t.filterInput.SetLabel("Filter: ")
		t.filterInput.SetLabelColor(tcell.ColorWhite)
	}

	// Display options
	dnsStatus := "[gray]off[white]"
	if t.showDNS {
		dnsStatus = "[green]on[white]"
	}
	svcStatus := "[gray]off[white]"
	if t.showService {
		svcStatus = "[green]on[white]"
	}

	// Shortcuts hint
	sortLine := "[gray]1[white]=time [gray]2[white]=bytes [gray]3[white]=pkts [gray]4[white]=src [gray]5[white]=dst [gray]6[white]=proto [gray]r[white]=rev"
	optionsLine := "[gray]n[white]=dns:%s [gray]e[white]=svc:%s [gray]v[white]=ver [gray]c[white]=clear"

	text := fmt.Sprintf(
		"[yellow]Sort:[white] %s %s\n%s\n"+optionsLine,
		t.sortField.String(),
		sortDir,
		sortLine,
		dnsStatus,
		svcStatus,
	)
	t.filterView.SetText(text)
}

func (t *TUI) updateTable() {
	// Get flows with current filter and sort
	flows := t.store.Query(&t.filter, t.sortField, t.sortAsc, 1000)

	// Save for detail view access
	t.currentFlows = flows

	// Remember current selection
	selectedRow, _ := t.table.GetSelection()

	// Clear existing rows (keep header)
	rowCount := t.table.GetRowCount()
	for i := rowCount - 1; i > 0; i-- {
		t.table.RemoveRow(i)
	}

	// Add flow rows
	for i, flow := range flows {
		row := i + 1 // +1 for header

		// Format source and destination
		src := t.formatFlowEndpoint(flow.SrcAddr.String(), flow.SrcPort, flow.Protocol)
		dst := t.formatFlowEndpoint(flow.DstAddr.String(), flow.DstPort, flow.Protocol)
		age := time.Since(flow.ReceivedAt).Truncate(time.Second).String()

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

		cols := t.getColumns()
		col := 0

		// Helper to pad text to column width (high water mark)
		padTo := func(s string, colIdx int, minWidth int) string {
			width := t.getColWidth(colIdx, s, minWidth)
			if len(s) < width {
				return s + strings.Repeat(" ", width-len(s))
			}
			return s
		}

		if t.showVersion {
			verShort := "v5"
			verColor := tcell.ColorWhite
			switch flow.Version {
			case types.NetFlowV9:
				verShort = "v9"
				verColor = tcell.ColorLightBlue
			case types.IPFIX:
				verShort = "IPFIX"
				verColor = tcell.ColorLightGreen
			}
			t.table.SetCell(row, col, tview.NewTableCell(padTo(verShort, col, cols[col].minWidth)).SetTextColor(verColor).SetExpansion(1))
			col++
		}

		t.table.SetCell(row, col, tview.NewTableCell(padTo(src, col, cols[col].minWidth)).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(padTo(dst, col, cols[col].minWidth)).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(padTo(protoDisplay, col, cols[col].minWidth)).SetTextColor(protoColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(padTo(formatBytes(flow.Bytes), col, cols[col].minWidth)).SetAlign(tview.AlignRight).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(padTo(fmt.Sprintf("%d", flow.Packets), col, cols[col].minWidth)).SetAlign(tview.AlignRight).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(padTo(flow.TCPFlagsString(), col, cols[col].minWidth)).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(padTo(age, col, cols[col].minWidth)).SetExpansion(1))
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

// parseIP parses an IP string to net.IP
func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func (t *TUI) refresh() {
	if t.paused || t.showHelp || t.showDetail {
		return
	}

	// Check if terminal was resized smaller - reset column widths
	_, _, width, _ := t.table.GetInnerRect()
	if t.lastWidth > 0 && width < t.lastWidth {
		t.resetColWidths()
	}
	t.lastWidth = width

	t.updateStats()
	t.updateFilterView()
	t.updateTable()

	// Always update cumulative interface stats
	t.updateInterfaceStats()

	// Update interface table display if on that page
	if t.currentPage == 1 {
		t.updateInterfaceTable()
	}

	// Update IP detail modal if visible
	if t.ipDetailVisible {
		t.updateIPDetailTable()
	}
}

// Run starts the TUI
func (t *TUI) Run() error {
	// Start refresh loop
	go func() {
		ticker := time.NewTicker(t.refreshRate)
		defer ticker.Stop()

		for {
			select {
			case <-t.stopChan:
				return
			case <-ticker.C:
				t.app.QueueUpdateDraw(t.refresh)
			}
		}
	}()

	// Initial refresh
	t.refresh()

	return t.app.Run()
}

// Stop stops the TUI
func (t *TUI) Stop() {
	close(t.stopChan)
	t.app.Stop()
}
