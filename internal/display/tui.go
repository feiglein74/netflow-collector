package display

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	pages       *tview.Pages // For overlay dropdown

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
		app:           tview.NewApplication(),
		store:         s,
		resolver:      resolver.New(),
		sortField:     store.SortByTime,
		sortAsc:       false,
		showService:   true, // Enable service names by default
		refreshRate:   refreshRate,
		stopChan:      make(chan struct{}),
		filterHistory: loadFilterHistory(),
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
	t.table.SetBorder(true).SetTitle(" Flows ")

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
		case tcell.KeyTab, tcell.KeyEnter:
			if t.dropdownVisible && t.dropdown.GetItemCount() > 0 {
				idx := t.dropdown.GetCurrentItem()
				if idx >= 0 && idx < len(t.suggestions) {
					t.filterInput.SetText(t.suggestions[idx])
				}
				t.hideDropdown()
				return nil
			}
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

	// Main layout
	t.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.filterInput, 3, 0, true).
		AddItem(topRow, 7, 0, false).
		AddItem(t.table, 0, 1, false)

	// Pages for overlay support
	t.pages = tview.NewPages().
		AddPage("main", t.layout, true, true)

	// Setup table headers
	t.setupTableHeaders()

	// Only Ctrl+C to quit - no other key bindings (for now)
	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlC {
			t.app.Stop()
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

func (t *TUI) showFlowDetail() {
	row, _ := t.table.GetSelection()
	if row <= 0 || row > len(t.currentFlows) {
		return
	}

	flow := t.currentFlows[row-1] // -1 for header row
	t.showDetail = true

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
	showingText := fmt.Sprintf("%d", filteredStats.Count)
	if !t.filter.IsEmpty() && t.filter.IsValid() {
		showingText = fmt.Sprintf("%d (%s, %d pkts)",
			filteredStats.Count,
			formatBytes(filteredStats.Bytes),
			filteredStats.Packets)
	}

	// Filter error line (if any)
	filterErrorLine := ""
	if t.filter.String() != "" && !t.filter.IsValid() && t.filter.Error != "" {
		filterErrorLine = "\n[red]Filter: " + tview.Escape(t.filter.Error) + "[white]"
	}

	text := fmt.Sprintf(
		"[yellow]Flows:[white] %d  [yellow]Bytes:[white] %s  [yellow]Rate:[white] %.1f/s  [yellow]Throughput:[white] %s/s%s\n"+
			"[yellow]Versions:[white] %s  [yellow]Exporters:[white] %d  [yellow]Showing:[white] %s%s",
		stats.TotalFlows,
		formatBytes(stats.TotalBytes),
		stats.FlowsPerSecond,
		formatBytes(uint64(stats.BytesPerSecond)),
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
