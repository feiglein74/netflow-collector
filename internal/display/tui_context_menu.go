package display

import (
	"fmt"
	"net"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/pkg/types"
)

// ContextMenuItem represents a menu item
type ContextMenuItem struct {
	Label  string
	Value  string
	Action func()
}

// showContextMenu displays a context menu at the current position as a floating overlay
func (t *TUI) showContextMenu(flow types.Flow, x, y int) {
	// Build menu items based on flow data
	items := t.buildContextMenuItems(flow)
	if len(items) == 0 {
		return
	}

	// Pause updates while context menu is open
	wasPaused := t.paused
	t.paused = true

	// Create a list for the menu
	menu := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorDarkCyan).
		SetMainTextColor(tcell.ColorWhite)

	menu.SetBorder(true).
		SetTitle(" Copy ").
		SetTitleAlign(tview.AlignLeft).
		SetBackgroundColor(tcell.ColorDarkSlateGray)

	// Helper to close menu and restore state
	closeMenu := func() {
		t.pages.RemovePage("contextmenu")
		t.paused = wasPaused // Restore previous pause state
		t.app.SetFocus(t.table)
	}

	// Add items
	for _, item := range items {
		capturedItem := item // Capture for closure
		menu.AddItem(item.Label, "", 0, func() {
			// Copy to clipboard
			copyToClipboard(capturedItem.Value)
			closeMenu()
		})
	}

	// Calculate menu size
	maxWidth := 0
	for _, item := range items {
		if len(item.Label) > maxWidth {
			maxWidth = len(item.Label)
		}
	}
	menuWidth := maxWidth + 6  // padding + border
	menuHeight := len(items) + 2 // items + border

	// Escape to close
	menu.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			closeMenu()
			return nil
		}
		return event
	})

	// Close on click outside menu
	menu.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		return action, event
	})

	// Get screen size
	_, _, screenWidth, screenHeight := t.pages.GetRect()

	// Adjust position if menu would go off screen
	if x+menuWidth > screenWidth {
		x = screenWidth - menuWidth
	}
	if y+menuHeight > screenHeight {
		y = screenHeight - menuHeight
	}
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	// Store menu position for the draw function
	menuX, menuY := x, y

	// Create a custom primitive that draws only the menu at the specified position
	overlay := tview.NewBox().SetDrawFunc(func(screen tcell.Screen, ox, oy, width, height int) (int, int, int, int) {
		// Return the exact position and size for the menu
		return menuX, menuY, menuWidth, menuHeight
	})

	// Wrap menu in a container that positions it correctly
	container := &menuOverlay{
		Box:       tview.NewBox(),
		menu:      menu,
		x:         menuX,
		y:         menuY,
		width:     menuWidth,
		height:    menuHeight,
		onDismiss: closeMenu,
	}

	// Add as transparent overlay (resize=false to not cover full screen)
	t.pages.AddPage("contextmenu", container, true, true)
	t.app.SetFocus(menu)
	_ = overlay // suppress unused warning
}

// menuOverlay is a custom primitive that shows a menu at a specific position
type menuOverlay struct {
	*tview.Box
	menu      *tview.List
	x, y      int
	width     int
	height    int
	onDismiss func()
}

// Draw draws the overlay - transparent background with menu at position
func (m *menuOverlay) Draw(screen tcell.Screen) {
	// Don't draw any background - let underlying content show through
	// Just draw the menu at the specified position
	m.menu.SetRect(m.x, m.y, m.width, m.height)
	m.menu.Draw(screen)
}

// InputHandler returns the input handler for this primitive
func (m *menuOverlay) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return m.menu.InputHandler()
}

// Focus delegates focus to the menu
func (m *menuOverlay) Focus(delegate func(p tview.Primitive)) {
	delegate(m.menu)
}

// HasFocus returns whether the menu has focus
func (m *menuOverlay) HasFocus() bool {
	return m.menu.HasFocus()
}

// MouseHandler handles mouse events - dismiss on click outside
func (m *menuOverlay) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
	return func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (consumed bool, capture tview.Primitive) {
		if action == tview.MouseLeftClick || action == tview.MouseRightClick {
			mx, my := event.Position()
			// Check if click is outside menu
			if mx < m.x || mx >= m.x+m.width || my < m.y || my >= m.y+m.height {
				m.onDismiss()
				return true, nil
			}
		}
		// Delegate to menu
		return m.menu.MouseHandler()(action, event, setFocus)
	}
}

// buildContextMenuItems builds the context menu items for a flow
func (t *TUI) buildContextMenuItems(flow types.Flow) []ContextMenuItem {
	var items []ContextMenuItem

	srcIP := flow.SrcAddr.String()
	dstIP := flow.DstAddr.String()

	// Source IP
	items = append(items, ContextMenuItem{
		Label: fmt.Sprintf("Src IP: %s", truncateForMenu(srcIP, 30)),
		Value: srcIP,
	})

	// Source hostname (if resolved)
	if srcHostname, _, found := t.resolver.GetCachedWithSource(flow.SrcAddr); found {
		items = append(items, ContextMenuItem{
			Label: fmt.Sprintf("Src Host: %s", truncateForMenu(srcHostname, 28)),
			Value: srcHostname,
		})
	}

	// Source IP:Port (if port > 0)
	if flow.SrcPort > 0 {
		srcEndpoint := fmt.Sprintf("%s:%d", srcIP, flow.SrcPort)
		items = append(items, ContextMenuItem{
			Label: fmt.Sprintf("Src Endpoint: %s", truncateForMenu(srcEndpoint, 25)),
			Value: srcEndpoint,
		})
	}

	// Separator-like spacing with dest items
	// Destination IP
	items = append(items, ContextMenuItem{
		Label: fmt.Sprintf("Dst IP: %s", truncateForMenu(dstIP, 30)),
		Value: dstIP,
	})

	// Destination hostname (if resolved)
	if dstHostname, _, found := t.resolver.GetCachedWithSource(flow.DstAddr); found {
		items = append(items, ContextMenuItem{
			Label: fmt.Sprintf("Dst Host: %s", truncateForMenu(dstHostname, 28)),
			Value: dstHostname,
		})
	}

	// Destination IP:Port (if port > 0)
	if flow.DstPort > 0 {
		dstEndpoint := fmt.Sprintf("%s:%d", dstIP, flow.DstPort)
		items = append(items, ContextMenuItem{
			Label: fmt.Sprintf("Dst Endpoint: %s", truncateForMenu(dstEndpoint, 25)),
			Value: dstEndpoint,
		})
	}

	// Flow key (5-tuple)
	flowKey := fmt.Sprintf("%s:%d -> %s:%d %s",
		srcIP, flow.SrcPort,
		dstIP, flow.DstPort,
		flow.ProtocolName())
	items = append(items, ContextMenuItem{
		Label: "Copy Flow (5-tuple)",
		Value: flowKey,
	})

	return items
}

// truncateForMenu truncates a string for menu display
func truncateForMenu(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

// getFlowAtRow returns the flow at the given table row
func (t *TUI) getFlowAtRow(row int) (types.Flow, bool) {
	if row <= 0 || row > len(t.currentFlows) {
		return types.Flow{}, false
	}
	return t.currentFlows[row-1], true
}

// setupMouseHandler sets up mouse event handling for context menus
func (t *TUI) setupMouseHandler() {
	t.table.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseRightClick {
			x, y := event.Position()

			// Convert screen position to table row
			_, tableY, _, _ := t.table.GetInnerRect()
			row := y - tableY

			// Get the flow at this row
			if flow, ok := t.getFlowAtRow(row); ok {
				t.showContextMenu(flow, x, y)
				return tview.MouseConsumed, nil
			}
		}
		return action, event
	})
}

// Helper to check if IP is valid
func isValidIP(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified()
}
