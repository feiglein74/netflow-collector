package display

import (
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/resolver"
	"netflow-collector/internal/store"
	"netflow-collector/pkg/types"
)

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
	interfaceTable      *tview.Table
	interfaceLayout     *tview.Flex
	currentPage         int                        // 0 = flows, 1 = interfaces
	interfaceStats      map[uint16]*InterfaceStats // Cumulative interface statistics
	lastInterfaceUpdate time.Time                  // Track when we last updated stats
	selectedInterfaces  map[uint16]bool            // Interfaces marked with Space for filtering

	// IP detail modal state
	ipDetailTable    *tview.Table
	ipDetailIfaceID  uint16
	ipDetailSelected map[string]bool
	ipDetailVisible  bool

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
	currentFlows         []types.Flow
	currentConversations []types.Conversation

	// Detail view state
	detailFlowKey    string // FlowKey of flow being shown in detail
	detailConvKey    string // ConversationKey being shown in detail
	convDetailLeft   *tview.TextView
	convDetailRight  *tview.TextView
	convDetailBottom *tview.TextView

	// BiFlow mode (F12 toggle)
	biflowMode bool

	// Flow aggregation (merge flows with same 5-tuple)
	aggregateFlows bool
}

// NewTUI creates a new interactive TUI
func NewTUI(s *store.FlowStore, refreshRate time.Duration) *TUI {
	if refreshRate == 0 {
		refreshRate = 500 * time.Millisecond
	}

	t := &TUI{
		app:                tview.NewApplication(),
		store:              s,
		resolver:           resolver.New(),
		sortField:          store.SortByTime,
		sortAsc:            false,
		showService:        true,  // Enable service names by default
		aggregateFlows:     true,  // Aggregate flows with same 5-tuple by default
		refreshRate:        refreshRate,
		stopChan:           make(chan struct{}),
		filterHistory:      loadFilterHistory(),
		interfaceStats:     make(map[uint16]*InterfaceStats),
		selectedInterfaces: make(map[uint16]bool),
	}

	t.setupUI()
	return t
}

// setupUI initializes all UI components
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
	t.table.SetBorder(true).SetTitle(" Flows [F2=Interfaces] [F12=BiFlow] ")

	// Interface statistics table
	t.interfaceTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	t.interfaceTable.SetBorder(true).SetTitle(" Interfaces [F1=Flows] [Space=Mark] [Enter=Filter] ")
	t.setupInterfaceTableHeaders()

	// Setup filter input with native autocomplete
	t.setupFilterInput()

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
	t.detailView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			t.hideFlowDetail()
			return nil
		}
		return event
	})

	// Setup key bindings
	t.setupKeyBindings()

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

	t.app.EnableMouse(true)
	t.app.SetRoot(t.pages, true)
	t.app.SetFocus(t.filterInput)
}

// setupKeyBindings configures all keyboard event handlers
func (t *TUI) setupKeyBindings() {
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

	// Flow table key handling
	t.table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:
			// Show detail view
			if t.biflowMode {
				t.showConversationDetail()
			} else {
				t.showFlowDetail()
			}
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case '1':
				t.toggleSort(store.SortBySrcIP)
				return nil
			case '2':
				t.toggleSort(store.SortByDstIP)
				return nil
			case '3':
				t.toggleSort(store.SortByProtocol)
				return nil
			case '4':
				t.toggleSort(store.SortByBytes)
				return nil
			case '5':
				t.toggleSort(store.SortByPackets)
				return nil
			case '6':
				t.toggleSort(store.SortByTime)
				return nil
			case ' ':
				t.paused = !t.paused
				return nil
			case '?':
				t.showHelp = !t.showHelp
				if t.showHelp {
					t.pages.AddPage("help", t.helpView, true, true)
				} else {
					t.pages.RemovePage("help")
				}
				return nil
			case 'q':
				t.app.Stop()
				return nil
			case 'n':
				t.showDNS = !t.showDNS
				return nil
			case 'e':
				t.showService = !t.showService
				t.setupTableHeaders()
				return nil
			case 'v':
				t.showVersion = !t.showVersion
				t.resetColWidths()
				t.setupTableHeaders()
				return nil
			case 'a':
				t.aggregateFlows = !t.aggregateFlows
				return nil
			case 'c':
				t.filter = store.Filter{}
				t.filterInput.SetText("")
				return nil
			case 'f':
				t.app.SetFocus(t.filterInput)
				return nil
			}
		}
		return event
	})

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
		// F12 toggles BiFlow mode
		if event.Key() == tcell.KeyF12 {
			t.biflowMode = !t.biflowMode
			t.resetColWidths() // Column layout changes
			t.setupTableHeaders()
			t.updateTableTitle()
			return nil
		}
		return event
	})
}

// columnDef defines a table column with minimum width and flex behavior
type columnDef struct {
	name     string
	minWidth int
	flex     bool // true = flexible column that shares remaining space
}

// updateTableTitle updates the flow table title based on current mode
func (t *TUI) updateTableTitle() {
	title := " Flows [F2=Interfaces] [F12=BiFlow] "
	if t.biflowMode {
		title = " BiFlow [F2=Interfaces] [F12=Flows] "
	}
	t.table.SetTitle(title)
}

// getColumns returns column definitions based on current display settings
func (t *TUI) getColumns() []columnDef {
	cols := []columnDef{}

	// BiFlow mode has different columns
	if t.biflowMode {
		protoCol := "Proto"
		if t.showService {
			protoCol = "Service"
		}
		cols = append(cols,
			columnDef{"Endpoint A", 18, true},  // 1 - flexible
			columnDef{"Endpoint B", 18, true},  // 2 - flexible
			columnDef{protoCol, 8, false},      // 3
			columnDef{"A→B", 10, false},        // 4
			columnDef{"B→A", 10, false},        // 5
			columnDef{"Total", 10, false},      // 6
			columnDef{"Time", 8, false},        // 7
			columnDef{"Age", 6, false},         // 8
		)
		return cols
	}

	// Normal flow mode
	// Column name depends on whether service names are shown
	protoCol := "Proto"
	if t.showService {
		protoCol = "Service"
	}

	cols = append(cols,
		columnDef{"Source", 18, true},      // 1 - flexible
		columnDef{"Destination", 18, true}, // 2 - flexible
		columnDef{protoCol, 8, false},      // 3
		columnDef{"Bytes", 8, false},       // 4
		columnDef{"Packets", 7, false},     // 5
		columnDef{"Time", 8, false},        // 6
		columnDef{"Age", 6, false},         // 7
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

// getFlexColumnMaxWidth calculates the max width for flexible columns based on available space
func (t *TUI) getFlexColumnMaxWidth() int {
	_, _, width, _ := t.table.GetInnerRect()
	if width <= 0 {
		width = 120 // Default fallback
	}

	cols := t.getColumns()

	// Calculate fixed width needed for non-flex columns
	fixedWidth := 0
	flexCount := 0
	for _, col := range cols {
		if col.flex {
			flexCount++
		} else {
			fixedWidth += col.minWidth + 2 // +2 for padding/separator
		}
	}

	// Calculate available space for flex columns
	availableForFlex := width - fixedWidth - 4 // -4 for borders
	if availableForFlex < 20*flexCount {
		availableForFlex = 20 * flexCount // Minimum 20 chars per flex column
	}

	// Divide equally among flex columns
	if flexCount > 0 {
		return availableForFlex / flexCount
	}
	return 40 // Fallback
}

// setupTableHeaders sets up the flow table headers
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

// updateTable updates the flow/conversation table based on current mode
func (t *TUI) updateTable() {
	if t.biflowMode {
		t.updateTableBiFlow()
	} else {
		t.updateTableFlows()
	}
}

// refresh updates all UI components
func (t *TUI) refresh() {
	if t.paused || t.showHelp {
		return
	}

	// Always update cumulative interface stats
	t.updateInterfaceStats()

	// If showing detail, just update the detail content (don't update table)
	if t.showDetail {
		t.refreshDetailContent()
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
