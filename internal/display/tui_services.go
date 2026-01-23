package display

import (
	"fmt"
	"sort"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"netflow-collector/internal/resolver"
	"netflow-collector/pkg/types"
)

// ServiceStats holds aggregated statistics for a service/port
type ServiceStats struct {
	Port        uint16
	Protocol    uint8
	ServiceName string
	FlowCount   int
	Bytes       uint64
	Packets     uint64
	UniqueSrc   map[string]bool // Unique source IPs
	UniqueDst   map[string]bool // Unique destination IPs
}

// ServiceSortField defines how to sort service statistics
type ServiceSortField int

const (
	ServiceSortByFlows ServiceSortField = iota
	ServiceSortByBytes
	ServiceSortByPackets
	ServiceSortByPort
	ServiceSortByName
)

// setupServiceTable initializes the service statistics table
func (t *TUI) setupServiceTable() {
	t.serviceTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	t.serviceTable.SetBorder(true).SetTitle(" Services [F1=Flows] [F2=Interfaces] ")

	// Setup headers
	t.setupServiceTableHeaders()

	// Key handling for service table
	t.serviceTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyF1:
			t.switchToPage(0)
			return nil
		case tcell.KeyF2:
			t.switchToPage(1)
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case ' ':
				t.paused = !t.paused
				return nil
			case '1':
				t.serviceSortField = ServiceSortByPort
				return nil
			case '2':
				t.serviceSortField = ServiceSortByName
				return nil
			case '3':
				t.serviceSortField = ServiceSortByFlows
				return nil
			case '4':
				t.serviceSortField = ServiceSortByBytes
				return nil
			case '5':
				t.serviceSortField = ServiceSortByPackets
				return nil
			case 'r':
				t.serviceSortAsc = !t.serviceSortAsc
				return nil
			case 'q':
				t.app.Stop()
				return nil
			case 'f':
				t.app.SetFocus(t.filterInput)
				return nil
			case 'c':
				t.filter.Raw = ""
				t.filter.Root = nil
				t.filterInput.SetText("")
				return nil
			}
		case tcell.KeyEnter:
			// Apply filter for selected service
			row, _ := t.serviceTable.GetSelection()
			if row > 0 && row <= len(t.currentServiceStats) {
				svc := t.currentServiceStats[row-1]
				var filterStr string
				if svc.ServiceName != "" {
					filterStr = fmt.Sprintf("service=%s", svc.ServiceName)
				} else {
					filterStr = fmt.Sprintf("port=%d", svc.Port)
				}
				t.filterInput.SetText(filterStr)
				t.applyFilter()
				t.switchToPage(0)
				return nil
			}
		}
		return event
	})
}

// setupServiceTableHeaders sets up the column headers
func (t *TUI) setupServiceTableHeaders() {
	headers := []string{"Port", "Service", "Proto", "Flows", "Bytes", "Packets", "Src IPs", "Dst IPs"}
	for i, h := range headers {
		cell := tview.NewTableCell(h).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false).
			SetAlign(tview.AlignLeft)
		if i >= 3 { // Right-align numeric columns
			cell.SetAlign(tview.AlignRight)
		}
		t.serviceTable.SetCell(0, i, cell)
	}
}

// updateServiceTable updates the service statistics table
func (t *TUI) updateServiceTable() {
	if t.paused {
		return
	}

	// Get flows (filtered if filter active)
	var flows []types.Flow
	if t.filter.IsEmpty() || !t.filter.IsValid() {
		flows = t.store.Query(nil, 0, false, 0)
	} else {
		flows = t.store.Query(&t.filter, 0, false, 0)
	}

	// Aggregate by service/port
	serviceMap := make(map[string]*ServiceStats)

	for _, flow := range flows {
		// Use destination port as the service identifier
		port := flow.DstPort
		proto := flow.Protocol

		// Create a key combining port and protocol
		key := fmt.Sprintf("%d/%d", port, proto)

		stats, exists := serviceMap[key]
		if !exists {
			serviceName := resolver.GetServiceName(port, proto)
			if serviceName == "" {
				// Try source port
				serviceName = resolver.GetServiceName(flow.SrcPort, proto)
				if serviceName != "" {
					port = flow.SrcPort
					key = fmt.Sprintf("%d/%d", port, proto)
					if existing, ok := serviceMap[key]; ok {
						stats = existing
						exists = true
					}
				}
			}
			if !exists {
				stats = &ServiceStats{
					Port:        port,
					Protocol:    proto,
					ServiceName: serviceName,
					UniqueSrc:   make(map[string]bool),
					UniqueDst:   make(map[string]bool),
				}
				serviceMap[key] = stats
			}
		}

		stats.FlowCount++
		stats.Bytes += flow.Bytes
		stats.Packets += flow.Packets
		stats.UniqueSrc[flow.SrcAddr.String()] = true
		stats.UniqueDst[flow.DstAddr.String()] = true
	}

	// Convert to slice
	var serviceList []*ServiceStats
	for _, s := range serviceMap {
		serviceList = append(serviceList, s)
	}

	// Sort
	sort.Slice(serviceList, func(i, j int) bool {
		var less bool
		switch t.serviceSortField {
		case ServiceSortByPort:
			less = serviceList[i].Port < serviceList[j].Port
		case ServiceSortByName:
			less = serviceList[i].ServiceName < serviceList[j].ServiceName
		case ServiceSortByFlows:
			less = serviceList[i].FlowCount < serviceList[j].FlowCount
		case ServiceSortByBytes:
			less = serviceList[i].Bytes < serviceList[j].Bytes
		case ServiceSortByPackets:
			less = serviceList[i].Packets < serviceList[j].Packets
		default:
			less = serviceList[i].Bytes < serviceList[j].Bytes
		}
		if !t.serviceSortAsc {
			less = !less
		}
		return less
	})

	// Store for reference
	t.currentServiceStats = serviceList

	// Update table
	// Clear existing rows (keep header)
	for row := t.serviceTable.GetRowCount() - 1; row > 0; row-- {
		t.serviceTable.RemoveRow(row)
	}

	// Add rows
	for i, svc := range serviceList {
		row := i + 1

		// Port
		t.serviceTable.SetCell(row, 0, tview.NewTableCell(fmt.Sprintf("%d", svc.Port)).
			SetAlign(tview.AlignRight))

		// Service name
		serviceName := svc.ServiceName
		if serviceName == "" {
			serviceName = "[gray]-[white]"
		}
		t.serviceTable.SetCell(row, 1, tview.NewTableCell(serviceName))

		// Protocol
		protoName := protocolName(svc.Protocol)
		t.serviceTable.SetCell(row, 2, tview.NewTableCell(protoName))

		// Flows
		t.serviceTable.SetCell(row, 3, tview.NewTableCell(formatNumber(svc.FlowCount)).
			SetAlign(tview.AlignRight))

		// Bytes
		t.serviceTable.SetCell(row, 4, tview.NewTableCell(formatBytes(svc.Bytes)).
			SetAlign(tview.AlignRight))

		// Packets
		t.serviceTable.SetCell(row, 5, tview.NewTableCell(formatNumber(int(svc.Packets))).
			SetAlign(tview.AlignRight))

		// Unique Src IPs
		t.serviceTable.SetCell(row, 6, tview.NewTableCell(formatNumber(len(svc.UniqueSrc))).
			SetAlign(tview.AlignRight))

		// Unique Dst IPs
		t.serviceTable.SetCell(row, 7, tview.NewTableCell(formatNumber(len(svc.UniqueDst))).
			SetAlign(tview.AlignRight))
	}

	// Update title with sort info
	sortName := ""
	switch t.serviceSortField {
	case ServiceSortByPort:
		sortName = "Port"
	case ServiceSortByName:
		sortName = "Name"
	case ServiceSortByFlows:
		sortName = "Flows"
	case ServiceSortByBytes:
		sortName = "Bytes"
	case ServiceSortByPackets:
		sortName = "Packets"
	}
	sortDir := "↓"
	if t.serviceSortAsc {
		sortDir = "↑"
	}
	t.serviceTable.SetTitle(fmt.Sprintf(" Services [%s %s] [F1=Flows] [F2=Interfaces] ", sortName, sortDir))
}

// protocolName returns protocol name for display
func protocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}
