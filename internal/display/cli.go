package display

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"netflow-collector/internal/store"
	"netflow-collector/pkg/types"
)

// ViewMode determines what to display
type ViewMode int

const (
	ViewRecent ViewMode = iota
	ViewTopBytes
	ViewTopPackets
	ViewStats
)

// CLI handles terminal display
type CLI struct {
	store       *store.FlowStore
	refreshRate time.Duration
	viewMode    ViewMode
	stopChan    chan struct{}
}

// New creates a new CLI display
func New(s *store.FlowStore, refreshRate time.Duration) *CLI {
	if refreshRate == 0 {
		refreshRate = time.Second
	}
	return &CLI{
		store:       s,
		refreshRate: refreshRate,
		viewMode:    ViewRecent,
		stopChan:    make(chan struct{}),
	}
}

// SetViewMode sets the display mode
func (c *CLI) SetViewMode(mode ViewMode) {
	c.viewMode = mode
}

// getTerminalSize returns current terminal width and height
func getTerminalSize() (width, height int) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		// Fallback to reasonable defaults
		return 100, 24
	}
	return width, height
}

// Start begins the display loop
func (c *CLI) Start() {
	ticker := time.NewTicker(c.refreshRate)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.render()
		}
	}
}

// Stop stops the display loop
func (c *CLI) Stop() {
	close(c.stopChan)
}

// render updates the terminal display
func (c *CLI) render() {
	width, height := getTerminalSize()

	// Clear screen
	fmt.Print("\033[2J\033[H")

	c.renderHeader(width)
	c.renderStats(width)
	fmt.Println()

	// Calculate available rows for flow display
	// Header: 3 lines, Stats: 2 lines, blank: 1, title+header: 3, footer: 2, buffer: 1
	usedRows := 12
	maxRows := height - usedRows
	if maxRows < 1 {
		maxRows = 1
	}

	switch c.viewMode {
	case ViewRecent:
		c.renderFlows("Recent Flows", c.store.GetRecent(maxRows), width)
	case ViewTopBytes:
		c.renderFlows("Top Flows by Bytes", c.store.GetTopByBytes(maxRows), width)
	case ViewTopPackets:
		c.renderFlows("Top Flows by Packets", c.store.GetTopByPackets(maxRows), width)
	case ViewStats:
		c.renderDetailedStats()
	}

	c.renderFooter(width)
}

func (c *CLI) renderHeader(width int) {
	// Adaptive header based on terminal width
	if width < 60 {
		fmt.Println("═══ NetFlow/IPFIX Collector ═══")
		return
	}

	title := "NetFlow/IPFIX Collector"
	innerWidth := width - 2
	if innerWidth < len(title) {
		innerWidth = len(title)
	}

	padding := (innerWidth - len(title)) / 2
	paddingRight := innerWidth - len(title) - padding

	fmt.Println("╔" + strings.Repeat("═", innerWidth) + "╗")
	fmt.Println("║" + strings.Repeat(" ", padding) + title + strings.Repeat(" ", paddingRight) + "║")
	fmt.Println("╚" + strings.Repeat("═", innerWidth) + "╝")
}

func (c *CLI) renderStats(width int) {
	stats := c.store.GetStats()

	if width >= 100 {
		fmt.Printf("│ Flows: %d │ Bytes: %s │ Packets: %d │ Rate: %.1f flows/s │ Throughput: %s/s │\n",
			stats.TotalFlows,
			formatBytes(stats.TotalBytes),
			stats.TotalPackets,
			stats.FlowsPerSecond,
			formatBytes(uint64(stats.BytesPerSecond)),
		)
		fmt.Printf("│ v5: %d │ v9: %d │ IPFIX: %d │ Exporters: %d │ Stored: %d │\n",
			stats.V5Flows,
			stats.V9Flows,
			stats.IPFIXFlows,
			stats.UniqueExporters,
			c.store.GetFlowCount(),
		)
	} else {
		// Compact stats for narrow terminals
		fmt.Printf("Flows: %d  Bytes: %s  Rate: %.1f/s\n",
			stats.TotalFlows,
			formatBytes(stats.TotalBytes),
			stats.FlowsPerSecond,
		)
		fmt.Printf("v5: %d  v9: %d  IPFIX: %d  Stored: %d\n",
			stats.V5Flows,
			stats.V9Flows,
			stats.IPFIXFlows,
			c.store.GetFlowCount(),
		)
	}
}

func (c *CLI) renderFlows(title string, flows []types.Flow, width int) {
	fmt.Printf("\n=== %s ===\n\n", title)

	if len(flows) == 0 {
		fmt.Println("No flows received yet. Waiting for data...")
		return
	}

	// Calculate column widths based on terminal width
	// Minimum: Version(10) + Src(15) + Dst(15) + Proto(5) + Bytes(10) + Pkts(8) + Flags(6) + spacing(12) = ~81
	if width >= 120 {
		// Wide terminal - full details with longer addresses
		srcWidth := 25
		dstWidth := 25

		fmt.Printf("%-12s %-*s %-*s %-5s %12s %10s %-6s\n",
			"Version", srcWidth, "Source", dstWidth, "Destination", "Proto", "Bytes", "Packets", "Flags")
		fmt.Println(strings.Repeat("─", width-1))

		for _, flow := range flows {
			src := formatEndpoint(flow.SrcAddr.String(), flow.SrcPort)
			dst := formatEndpoint(flow.DstAddr.String(), flow.DstPort)

			fmt.Printf("%-12s %-*s %-*s %-5s %12s %10d %-6s\n",
				flow.Version.String(),
				srcWidth, truncate(src, srcWidth),
				dstWidth, truncate(dst, dstWidth),
				flow.ProtocolName(),
				formatBytes(flow.Bytes),
				flow.Packets,
				flow.TCPFlagsString(),
			)
		}
	} else if width >= 90 {
		// Medium terminal
		srcWidth := 21
		dstWidth := 21

		fmt.Printf("%-10s %-*s %-*s %-5s %10s %8s %-5s\n",
			"Version", srcWidth, "Source", dstWidth, "Destination", "Proto", "Bytes", "Pkts", "Flags")
		fmt.Println(strings.Repeat("─", width-1))

		for _, flow := range flows {
			src := formatEndpoint(flow.SrcAddr.String(), flow.SrcPort)
			dst := formatEndpoint(flow.DstAddr.String(), flow.DstPort)

			fmt.Printf("%-10s %-*s %-*s %-5s %10s %8d %-5s\n",
				flow.Version.String(),
				srcWidth, truncate(src, srcWidth),
				dstWidth, truncate(dst, dstWidth),
				flow.ProtocolName(),
				formatBytes(flow.Bytes),
				flow.Packets,
				flow.TCPFlagsString(),
			)
		}
	} else {
		// Narrow terminal - compact view
		srcWidth := 15
		dstWidth := 15

		fmt.Printf("%-8s %-*s %-*s %-4s %8s\n",
			"Ver", srcWidth, "Source", dstWidth, "Dest", "Pro", "Bytes")
		fmt.Println(strings.Repeat("─", width-1))

		for _, flow := range flows {
			src := formatEndpoint(flow.SrcAddr.String(), flow.SrcPort)
			dst := formatEndpoint(flow.DstAddr.String(), flow.DstPort)

			verShort := "v5"
			switch flow.Version {
			case types.NetFlowV9:
				verShort = "v9"
			case types.IPFIX:
				verShort = "IPFIX"
			}

			fmt.Printf("%-8s %-*s %-*s %-4s %8s\n",
				verShort,
				srcWidth, truncate(src, srcWidth),
				dstWidth, truncate(dst, dstWidth),
				flow.ProtocolName(),
				formatBytes(flow.Bytes),
			)
		}
	}
}

func (c *CLI) renderDetailedStats() {
	stats := c.store.GetStats()

	fmt.Print("\n=== Detailed Statistics ===\n\n")

	fmt.Printf("Total Flows Received:    %d\n", stats.TotalFlows)
	fmt.Printf("Total Bytes:             %s\n", formatBytes(stats.TotalBytes))
	fmt.Printf("Total Packets:           %d\n", stats.TotalPackets)
	fmt.Println()
	fmt.Printf("Current Rate:            %.2f flows/second\n", stats.FlowsPerSecond)
	fmt.Printf("Current Throughput:      %s/second\n", formatBytes(uint64(stats.BytesPerSecond)))
	fmt.Println()
	fmt.Printf("NetFlow v5 Flows:        %d\n", stats.V5Flows)
	fmt.Printf("NetFlow v9 Flows:        %d\n", stats.V9Flows)
	fmt.Printf("IPFIX Flows:             %d\n", stats.IPFIXFlows)
	fmt.Println()
	fmt.Printf("Unique Exporters:        %d\n", stats.UniqueExporters)
	fmt.Printf("Flows in Memory:         %d\n", c.store.GetFlowCount())
}

func (c *CLI) renderFooter(width int) {
	fmt.Println()
	fmt.Println(strings.Repeat("─", width-1))
	fmt.Printf("Press Ctrl+C to exit │ Updated: %s │ Terminal: %dx\n",
		time.Now().Format("15:04:05"), width)
}

// NOTE: formatBytes, formatNumber, formatDecimal are defined in tui_helpers.go

// formatEndpoint formats IP:port
func formatEndpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// truncate truncates a string to maxLen
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

// RenderOnce renders the display once (useful for non-interactive mode)
func (c *CLI) RenderOnce(output *os.File) {
	stats := c.store.GetStats()
	width, height := getTerminalSize()
	maxRows := height - 5
	if maxRows < 5 {
		maxRows = 5
	}
	flows := c.store.GetRecent(maxRows)

	fmt.Fprintf(output, "Stats: %d flows, %s, %.1f flows/s (terminal: %dx%d)\n",
		stats.TotalFlows,
		formatBytes(stats.TotalBytes),
		stats.FlowsPerSecond,
		width, height,
	)

	for _, flow := range flows {
		fmt.Fprintf(output, "%s %s:%d -> %s:%d %s %s %d pkts\n",
			flow.Version.String(),
			flow.SrcAddr, flow.SrcPort,
			flow.DstAddr, flow.DstPort,
			flow.ProtocolName(),
			formatBytes(flow.Bytes),
			flow.Packets,
		)
	}
}
