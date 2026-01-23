package display

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/store"
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

// clearFilter clears the current filter
func (t *TUI) clearFilter() {
	t.filter = store.Filter{}
}

// applyFilter parses the current filter input text and applies it
func (t *TUI) applyFilter() {
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
	// Return focus to table after applying filter
	t.app.SetFocus(t.table)
}

// setupFilterInput creates and configures the filter input field with native autocomplete
func (t *TUI) setupFilterInput() {
	t.filterInput = tview.NewInputField().
		SetLabel(" Filter: ").
		SetFieldWidth(0).
		SetFieldBackgroundColor(tcell.ColorDarkBlue)
	t.filterInput.SetBorder(true).SetTitle(" Filter (Enter=Apply, Esc=Table, Tab=Complete) ")

	// Native tview autocomplete
	t.filterInput.SetAutocompleteFunc(func(currentText string) []string {
		return t.getFilterSuggestions(currentText)
	})

	// Handle Enter and Escape
	t.filterInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			t.applyFilter()
		} else if key == tcell.KeyEscape {
			t.app.SetFocus(t.table)
		}
	})
}

// getFilterSuggestions returns autocomplete suggestions based on current input
func (t *TUI) getFilterSuggestions(currentText string) []string {
	// If empty, show history
	if currentText == "" {
		if len(t.filterHistory) > 0 {
			max := 5
			if len(t.filterHistory) < max {
				max = len(t.filterHistory)
			}
			return t.filterHistory[:max]
		}
		return nil
	}

	var suggestions []string

	// Always include current text as first option (so Enter preserves what user typed)
	suggestions = append(suggestions, currentText)

	// Parse input to understand context
	words := strings.Fields(currentText)
	if len(words) == 0 {
		return suggestions
	}

	// Get the last word being typed
	lastWord := words[len(words)-1]
	prefix := strings.ToLower(lastWord)

	// Check if user just finished a word (space at end)
	if strings.HasSuffix(currentText, " ") {
		prefix = ""
		lastWord = ""
	}

	// Handle negation prefix
	negationPrefix := ""
	fieldPart := prefix
	if strings.HasPrefix(prefix, "!") {
		negationPrefix = "!"
		fieldPart = prefix[1:]
	} else if strings.HasPrefix(prefix, "-") {
		negationPrefix = "-"
		fieldPart = prefix[1:]
	}

	// Build prefix for completed suggestions (everything before current word)
	existingText := ""
	if len(words) > 1 || (len(words) == 1 && strings.HasSuffix(currentText, " ")) {
		if strings.HasSuffix(currentText, " ") {
			existingText = currentText
		} else {
			existingText = strings.Join(words[:len(words)-1], " ") + " "
		}
	}

	// Check if we're completing a field value (after = or :)
	if strings.Contains(fieldPart, "=") || strings.Contains(fieldPart, ":") {
		// Split on = or :
		var parts []string
		var sep string
		if strings.Contains(fieldPart, "=") {
			parts = strings.SplitN(fieldPart, "=", 2)
			sep = "="
		} else {
			parts = strings.SplitN(fieldPart, ":", 2)
			sep = ":"
		}

		if len(parts) == 2 {
			field := parts[0]
			valuePart := parts[1]

			values := t.getFieldValueSuggestions(field, valuePart)
			for _, v := range values {
				suggestion := existingText + negationPrefix + field + sep + v
				if suggestion != currentText {
					suggestions = append(suggestions, suggestion)
				}
			}
		}
	} else {
		// Suggest field names
		fieldNames := []string{
			"src=", "dst=", "ip=", "host=",
			"port:", "srcport:", "dstport:",
			"proto=", "service=", "svc=",
			"if=", "inif=", "outif=",
		}

		for _, f := range fieldNames {
			if fieldPart == "" || strings.HasPrefix(strings.ToLower(f), fieldPart) {
				suggestion := existingText + negationPrefix + f
				if suggestion != currentText {
					suggestions = append(suggestions, suggestion)
				}
			}
		}

		// Suggest operators if we have a complete condition
		if fieldPart == "" && existingText != "" {
			operators := []string{"&& ", "|| "}
			for _, op := range operators {
				suggestion := existingText + op
				if suggestion != currentText {
					suggestions = append(suggestions, suggestion)
				}
			}
		}

		// Match history entries
		for _, h := range t.filterHistory {
			if strings.HasPrefix(strings.ToLower(h), strings.ToLower(currentText)) && h != currentText {
				suggestions = append(suggestions, h)
			}
		}
	}

	// Deduplicate and limit
	seen := make(map[string]bool)
	unique := []string{}
	for _, s := range suggestions {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}

	if len(unique) > 10 {
		unique = unique[:10]
	}

	// Return nil if only current text (no real suggestions)
	if len(unique) <= 1 {
		return nil
	}

	return unique
}

// getFieldValueSuggestions returns value suggestions for a specific field
func (t *TUI) getFieldValueSuggestions(field, valuePart string) []string {
	var values []string
	valuePart = strings.ToLower(valuePart)

	switch strings.ToLower(field) {
	case "proto", "protocol":
		protocols := []string{"tcp", "udp", "icmp", "gre", "esp", "ah"}
		for _, p := range protocols {
			if valuePart == "" || strings.HasPrefix(p, valuePart) {
				values = append(values, p)
			}
		}

	case "service", "svc":
		// Get services from current flows
		services := t.getSeenServices()
		for _, s := range services {
			if valuePart == "" || strings.HasPrefix(strings.ToLower(s), valuePart) {
				values = append(values, s)
			}
		}

	case "port", "srcport", "dstport":
		// Get ports from current flows
		ports := t.getSeenPorts()
		for _, p := range ports {
			if valuePart == "" || strings.HasPrefix(p, valuePart) {
				values = append(values, p)
			}
		}

	case "src", "dst", "ip", "host":
		// Get IPs from current flows
		ips := t.getSeenIPs()
		for _, ip := range ips {
			if valuePart == "" || strings.HasPrefix(strings.ToLower(ip), valuePart) {
				values = append(values, ip)
			}
		}

	case "if", "inif", "outif":
		// Get interfaces from current flows
		ifaces := t.getSeenInterfaces()
		for _, iface := range ifaces {
			if valuePart == "" || strings.HasPrefix(iface, valuePart) {
				values = append(values, iface)
			}
		}
	}

	// Limit results
	if len(values) > 15 {
		values = values[:15]
	}

	return values
}

// updateFilterView updates the filter status display
func (t *TUI) updateFilterView() {
	sortDir := "DESC"
	if t.sortAsc {
		sortDir = "ASC"
	}

	// Update filter input label with status
	if t.filter.String() != "" {
		if !t.filter.IsValid() {
			t.filterInput.SetLabel(" Filter [ERR]: ")
			t.filterInput.SetLabelColor(tcell.ColorRed)
		} else {
			matchCount := t.store.GetFilteredCount(&t.filter)
			if matchCount == 0 {
				t.filterInput.SetLabel(" Filter [0]: ")
				t.filterInput.SetLabelColor(tcell.ColorYellow)
			} else {
				t.filterInput.SetLabel(fmt.Sprintf(" Filter [%s]: ", formatNumber(matchCount)))
				t.filterInput.SetLabelColor(tcell.ColorGreen)
			}
		}
	} else {
		t.filterInput.SetLabel(" Filter: ")
		t.filterInput.SetLabelColor(tcell.ColorWhite)
	}

	// Display options - DNS mode with color coding
	var dnsStatus string
	switch t.dnsMode {
	case DNSModeOff:
		dnsStatus = "[gray]OFF[white]"
	case DNSModeAll:
		dnsStatus = "[green]ALL[white]"
	case DNSModeReverse:
		dnsStatus = "[#00BFFF]REV[white]" // DeepSkyBlue for Reverse DNS
	case DNSModeTechnitium:
		dnsStatus = "[#FF8C00]TECH[white]" // DarkOrange for Technitium
	case DNSModeMDNS:
		dnsStatus = "[#9370DB]MDNS[white]" // MediumPurple for mDNS
	}
	svcStatus := "[gray]off[white]"
	if t.showService {
		svcStatus = "[green]on[white]"
	}
	aggStatus := "[gray]off[white]"
	if t.aggregateFlows {
		aggStatus = "[green]on[white]"
	}

	// Shortcuts hint
	sortLine := "[gray]1[white]=src [gray]2[white]=dst [gray]3[white]=proto [gray]4[white]=bytes [gray]5[white]=pkts [gray]6[white]=time [gray]r[white]=rev"
	optionsLine := "[gray]n[white]=dns:%s [gray]e[white]=svc:%s [gray]a[white]=agg:%s [gray]v[white]=ver [gray]c[white]=clear"

	text := fmt.Sprintf(
		"[yellow]Sort:[white] %s %s\n%s\n"+optionsLine,
		t.sortField.String(),
		sortDir,
		sortLine,
		dnsStatus,
		svcStatus,
		aggStatus,
	)
	t.filterView.SetText(text)
}

// getHelpText returns the help text for the help view
func (t *TUI) getHelpText() string {
	return `[yellow]NetFlow/IPFIX Collector - Keyboard Shortcuts[white]

[green]Navigation:[white]
  Up/Down, j/k    Scroll through flows
  PgUp/PgDn       Page up/down
  Home/End        Jump to start/end
  Enter           Show flow details

[green]Sorting:[white]
  1-6             Sort by Src/Dst/Proto/Bytes/Pkts/Time
  r               Reverse sort order (ASC/DESC)

[green]Filtering:[white]
  f               Focus filter input
  Tab             Complete suggestion
  Enter           Apply filter
  Esc             Return to table
  c               Clear filter

[green]Filter Syntax:[white]
  src=192.168     Source IP contains
  dst=10.0        Dest IP contains
  ip=8.8          Either src or dst
  port:443        Either port
  proto=tcp       Protocol
  service=https   Service name

[green]Filter Operators:[white]
  && or space     AND
  ||              OR
  ! or -          NOT (prefix)
  ( )             Grouping

[green]Examples:[white]
  src=192.168 proto=tcp
  port:80 || port:443
  !src=10.0.0.1 && service=dns

[green]Pages:[white]
  F1              Flow table
  F2              Interface statistics
  F12             Toggle BiFlow mode

[green]Display:[white]
  n               Toggle DNS resolution
  e               Toggle service names
  v               Toggle version column
  a               Toggle flow aggregation
  Space           Pause/Resume
  ?               This help
  q               Quit

Press ? or Esc to close`
}

// toggleHelp toggles the help view
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

// setSortField sets the sort field and toggles direction if same field
func (t *TUI) setSortField(field store.SortField) {
	if t.sortField == field {
		t.sortAsc = !t.sortAsc
	} else {
		t.sortField = field
		t.sortAsc = false
	}
}

// toggleSort changes sort field or toggles direction if same field
func (t *TUI) toggleSort(field store.SortField) {
	if t.sortField == field {
		t.sortAsc = !t.sortAsc
	} else {
		t.sortField = field
		t.sortAsc = false // Default: descending
	}
	t.setupTableHeaders()
}

// updateStats updates the statistics display
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
