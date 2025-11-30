package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"netflow-collector/internal/display"
	"netflow-collector/internal/listener"
	"netflow-collector/internal/parser"
	"netflow-collector/internal/store"
)

func main() {
	// Command line flags
	port := flag.Int("port", 2055, "UDP port to listen on")
	maxFlows := flag.Int("max-flows", 100000, "Maximum flows to keep in memory")
	refreshRate := flag.Duration("refresh", 500*time.Millisecond, "Display refresh rate")
	simple := flag.Bool("simple", false, "Use simple CLI instead of interactive TUI")

	// Eviction settings
	topKPercent := flag.Float64("topk-percent", 1.0, "Percent of max-flows to protect as elephant flows (1.0 = 1%)")
	lruWindow := flag.Duration("lru-window", 5*time.Minute, "Protect recently viewed flows for this duration")

	flag.Parse()

	// Create eviction config
	evictionConfig := store.EvictionConfig{
		TopKPercent: *topKPercent,
		LRUWindow:   *lruWindow,
	}

	// Create components
	udpListener := listener.New(*port)
	flowParser := parser.New()
	flowStore := store.NewWithConfig(*maxFlows, evictionConfig)

	// Start UDP listener
	if err := udpListener.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting listener: %v\n", err)
		os.Exit(1)
	}

	// Process packets in background
	go func() {
		for packet := range udpListener.Packets() {
			flows, err := flowParser.Parse(packet.Data, packet.SourceAddr)
			if err != nil {
				continue
			}
			flowStore.Add(flows)
		}
	}()

	if *simple {
		// Simple CLI mode
		cli := display.New(flowStore, *refreshRate)
		fmt.Printf("NetFlow/IPFIX Collector started on UDP port %d (simple mode)\n", *port)
		fmt.Println("Supported versions: NetFlow v5, v9, IPFIX (v10)")
		fmt.Println("Press Ctrl+C to exit")
		fmt.Println()

		// Run simple display in foreground
		cli.Start()
	} else {
		// Interactive TUI mode
		tui := display.NewTUI(flowStore, *refreshRate)

		// Run TUI (blocks until exit)
		if err := tui.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
			os.Exit(1)
		}
	}

	// Cleanup
	udpListener.Stop()

	// Print final stats
	stats := flowStore.GetStats()
	evictStats := flowStore.GetEvictionStats()
	fmt.Printf("\nFinal Statistics:\n")
	fmt.Printf("  Total Flows: %d\n", stats.TotalFlows)
	fmt.Printf("  Total Bytes: %d\n", stats.TotalBytes)
	fmt.Printf("  Total Packets: %d\n", stats.TotalPackets)
	fmt.Printf("  NetFlow v5: %d\n", stats.V5Flows)
	fmt.Printf("  NetFlow v9: %d\n", stats.V9Flows)
	fmt.Printf("  IPFIX: %d\n", stats.IPFIXFlows)
	if evictStats.TotalEvicted > 0 {
		fmt.Printf("\nEviction Statistics:\n")
		fmt.Printf("  Total Evicted: %d\n", evictStats.TotalEvicted)
		fmt.Printf("  TopK Protected: %d\n", evictStats.TopKProtected)
		fmt.Printf("  LRU Protected: %d\n", evictStats.LRUProtected)
	}
}
