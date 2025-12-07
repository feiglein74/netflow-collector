package display

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/resolver"
	"netflow-collector/pkg/types"
)

// showConversationDetail displays the detail view for the selected conversation
func (t *TUI) showConversationDetail() {
	row, _ := t.table.GetSelection()
	if row <= 0 || row > len(t.currentConversations) {
		return
	}

	conv := t.currentConversations[row-1]
	t.showDetail = true
	t.detailConvKey = conv.Key()
	t.detailFlowKey = "" // Clear flow key

	// Create reusable views if not already created
	if t.convDetailLeft == nil {
		t.convDetailLeft = tview.NewTextView().SetDynamicColors(true)
		t.convDetailLeft.SetBorder(true).SetTitle(" A → B ")
	}
	if t.convDetailRight == nil {
		t.convDetailRight = tview.NewTextView().SetDynamicColors(true)
		t.convDetailRight.SetBorder(true).SetTitle(" B → A ")
	}
	if t.convDetailBottom == nil {
		t.convDetailBottom = tview.NewTextView().SetDynamicColors(true)
		t.convDetailBottom.SetBorder(true).SetTitle(" Conversation Summary ")
	}

	// Update content
	t.updateConversationDetailContent(&conv)

	// Two columns at top, summary at bottom
	topRow := tview.NewFlex().
		AddItem(t.convDetailLeft, 0, 1, false).
		AddItem(t.convDetailRight, 0, 1, false)

	detailLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topRow, 0, 2, false).
		AddItem(t.convDetailBottom, 12, 0, true)

	// Handle Esc to close
	detailLayout.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			t.hideFlowDetail()
			return nil
		}
		return event
	})

	t.layout.Clear()
	t.layout.AddItem(detailLayout, 0, 1, true)
	t.app.SetFocus(detailLayout)
}

// updateConversationDetailContent updates the content of the conversation detail views
func (t *TUI) updateConversationDetailContent(conv *types.Conversation) {
	// Get service name
	service := ""
	if conv.PortA < conv.PortB && conv.PortA > 0 {
		service = resolver.GetServiceName(conv.PortA, conv.Protocol)
	} else if conv.PortB > 0 {
		service = resolver.GetServiceName(conv.PortB, conv.Protocol)
	}
	if service == "" {
		service = conv.ProtocolName()
	}

	// Bidirectional indicator
	biDir := "[red]No[white]"
	if conv.IsBidirectional() {
		biDir = "[green]Yes[white]"
	}

	leftText := fmt.Sprintf(`[yellow]═══ A → B ═══[white]

[green]Endpoint A:[white]
  %s:%d

[green]Endpoint B:[white]
  %s:%d

[green]Bytes:[white]      %s
[green]Packets:[white]    %d
[green]Flows:[white]      %d`,
		conv.AddrA, conv.PortA,
		conv.AddrB, conv.PortB,
		formatBytes(conv.BytesAtoB),
		conv.PacketsAtoB,
		conv.FlowsAtoB,
	)

	rightText := fmt.Sprintf(`[yellow]═══ B → A ═══[white]

[green]Endpoint B:[white]
  %s:%d

[green]Endpoint A:[white]
  %s:%d

[green]Bytes:[white]      %s
[green]Packets:[white]    %d
[green]Flows:[white]      %d`,
		conv.AddrB, conv.PortB,
		conv.AddrA, conv.PortA,
		formatBytes(conv.BytesBtoA),
		conv.PacketsBtoA,
		conv.FlowsBtoA,
	)

	bottomText := fmt.Sprintf(`
[yellow]═══ Summary ═══[white]
[green]Protocol:[white]       %s (%d)
[green]Service:[white]        %s
[green]Bidirectional:[white]  %s
[green]Total Bytes:[white]    %s
[green]Total Packets:[white]  %d
[green]First Seen:[white]     %s
[green]Last Seen:[white]      %s

[gray]Press Esc to close[white]`,
		conv.ProtocolName(), conv.Protocol,
		service,
		biDir,
		formatBytes(conv.TotalBytes()),
		conv.TotalPackets(),
		conv.FirstSeen.Format("15:04:05"),
		conv.LastSeen.Format("15:04:05"),
	)

	t.convDetailLeft.SetText(leftText)
	t.convDetailRight.SetText(rightText)
	t.convDetailBottom.SetText(bottomText)
}

// updateTableBiFlow updates the table with conversation/biflow data
func (t *TUI) updateTableBiFlow() {
	// Get conversations with current filter and sort
	conversations := t.store.QueryConversations(&t.filter, t.sortField, t.sortAsc, 1000)

	// Save for detail view access
	t.currentConversations = conversations

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

	// Add conversation rows
	for i, conv := range conversations {
		row := i + 1 // +1 for header

		// Format endpoints
		endpointA := t.formatFlowEndpoint(conv.AddrA.String(), conv.PortA, conv.Protocol)
		endpointB := t.formatFlowEndpoint(conv.AddrB.String(), conv.PortB, conv.Protocol)
		timeStr := conv.LastSeen.Format("15:04:05")
		ageStr := formatAge(time.Since(conv.LastSeen))

		// Detect service (use the lower port as it's usually the server)
		service := ""
		if t.showService {
			if conv.PortA < conv.PortB && conv.PortA > 0 {
				service = resolver.GetServiceName(conv.PortA, conv.Protocol)
			} else if conv.PortB > 0 {
				service = resolver.GetServiceName(conv.PortB, conv.Protocol)
			}
			if service == "" && conv.PortA > 0 {
				service = resolver.GetServiceName(conv.PortA, conv.Protocol)
			}
		}

		protoColor := tcell.ColorWhite
		switch conv.Protocol {
		case 6:
			protoColor = tcell.ColorLightCyan
		case 17:
			protoColor = tcell.ColorLightYellow
		case 1:
			protoColor = tcell.ColorLightPink
		}

		// Build protocol/service display
		protoDisplay := conv.ProtocolName()
		if service != "" {
			protoDisplay = service
		}

		// Format bytes per direction
		aToBStr := fmt.Sprintf("→%s", formatBytes(conv.BytesAtoB))
		bToAStr := fmt.Sprintf("←%s", formatBytes(conv.BytesBtoA))
		totalStr := formatBytes(conv.TotalBytes())

		// Color for unidirectional flows (yellow if only one direction)
		rowColor := tcell.ColorWhite
		if !conv.IsBidirectional() {
			rowColor = tcell.ColorYellow
		}

		col := 0
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(endpointA, col, cols[col], true)).SetTextColor(rowColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(endpointB, col, cols[col], true)).SetTextColor(rowColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(protoDisplay, col, cols[col], false)).SetTextColor(protoColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(aToBStr, col, cols[col], false)).SetAlign(tview.AlignRight).SetTextColor(rowColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(bToAStr, col, cols[col], false)).SetAlign(tview.AlignRight).SetTextColor(rowColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(totalStr, col, cols[col], false)).SetAlign(tview.AlignRight).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(timeStr, col, cols[col], false)).SetTextColor(rowColor).SetExpansion(1))
		col++
		t.table.SetCell(row, col, tview.NewTableCell(formatCol(ageStr, col, cols[col], false)).SetTextColor(rowColor).SetExpansion(1))
	}

	// Restore selection if valid
	if selectedRow > 0 && selectedRow < t.table.GetRowCount() {
		t.table.Select(selectedRow, 0)
	} else if t.table.GetRowCount() > 1 {
		t.table.Select(1, 0)
	}
}
