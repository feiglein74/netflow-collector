package main

import (
	"fmt"
	"os"
	"time"

	"netflow-collector/internal/display"
	"netflow-collector/internal/listener"
	"netflow-collector/internal/parser"
	"netflow-collector/internal/resolver"
	"netflow-collector/internal/store"

	"github.com/spf13/cobra"
)

var (
	// Flags
	port        int
	maxFlows    int
	refreshRate time.Duration
	simple      bool
	topKPercent float64
	lruWindow   time.Duration
	prefixLen   int

	// Technitium DNS flags
	dnsServer   string
	dnsToken    string
	dnsAppName  string
	dnsPollRate time.Duration
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netflow-collector",
		Short: "NetFlow/IPFIX collector with interactive TUI",
		Long: `A high-performance NetFlow/IPFIX collector that supports:
  - NetFlow v5 (fixed format)
  - NetFlow v9 (template-based)
  - IPFIX v10 (template-based)

Features interactive TUI with flow table, sorting, filtering,
DNS resolution, and service name mapping.`,
		Run: runCollector,
	}

	// Define flags
	rootCmd.Flags().IntVarP(&port, "port", "p", 2055, "UDP port to listen on")
	rootCmd.Flags().IntVarP(&maxFlows, "max-flows", "m", 100000, "Maximum flows to keep in memory")
	rootCmd.Flags().DurationVarP(&refreshRate, "refresh", "r", 500*time.Millisecond, "Display refresh rate")
	rootCmd.Flags().BoolVarP(&simple, "simple", "s", false, "Use simple CLI instead of interactive TUI")
	rootCmd.Flags().Float64Var(&topKPercent, "topk-percent", 1.0, "Percent of max-flows to protect as elephant flows (1.0 = 1%)")
	rootCmd.Flags().DurationVar(&lruWindow, "lru-window", 5*time.Minute, "Protect recently viewed flows for this duration")
	rootCmd.Flags().IntVar(&prefixLen, "prefix-len", 56, "IPv6 prefix length for own network detection (48, 56, 60, 64)")

	// Technitium DNS integration flags
	rootCmd.Flags().StringVar(&dnsServer, "dns-server", "", "Technitium DNS server URL (e.g., http://192.168.1.1:5380)")
	rootCmd.Flags().StringVar(&dnsToken, "dns-token", "", "Technitium DNS API token")
	rootCmd.Flags().StringVar(&dnsAppName, "dns-app", "Query Logs (Sqlite)", "Technitium DNS app name for query logs")
	rootCmd.Flags().DurationVar(&dnsPollRate, "dns-poll", 5*time.Second, "How often to poll Technitium for new DNS queries")

	// Add completion command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for the specified shell.

PowerShell:
  netflow-collector completion powershell | Out-String | Invoke-Expression

  To load completions for every new session, add the output to your profile:
  netflow-collector completion powershell >> $PROFILE

Bash:
  source <(netflow-collector completion bash)

  To load completions for every new session (Linux):
  netflow-collector completion bash > /etc/bash_completion.d/netflow-collector

Zsh:
  netflow-collector completion zsh > "${fpath[1]}/_netflow-collector"

Fish:
  netflow-collector completion fish > ~/.config/fish/completions/netflow-collector.fish
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runCollector(cmd *cobra.Command, args []string) {
	// Create eviction config
	evictionConfig := store.EvictionConfig{
		TopKPercent: topKPercent,
		LRUWindow:   lruWindow,
	}

	// Create components
	udpListener := listener.New(port)
	flowParser := parser.New()
	flowStore := store.NewWithConfig(maxFlows, evictionConfig)

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

	// Technitium DNS client (for DNS enrichment)
	var techClient *resolver.TechnitiumClient

	if simple {
		// Simple CLI mode
		cli := display.New(flowStore, refreshRate)
		fmt.Printf("NetFlow/IPFIX Collector started on UDP port %d (simple mode)\n", port)
		fmt.Println("Supported versions: NetFlow v5, v9, IPFIX (v10)")
		fmt.Println("Press Ctrl+C to exit")
		fmt.Println()

		// Run simple display in foreground
		cli.Start()
	} else {
		// Interactive TUI mode
		tui := display.NewTUI(flowStore, refreshRate, prefixLen)

		// Start Technitium DNS integration if configured
		if dnsServer != "" && dnsToken != "" {
			techClient = resolver.NewTechnitiumClient(resolver.TechnitiumConfig{
				ServerURL:    dnsServer,
				Token:        dnsToken,
				AppName:      dnsAppName,
				PollInterval: dnsPollRate,
			}, tui.GetResolver())

			if err := techClient.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to start Technitium DNS client: %v\n", err)
			}
		}

		// Run TUI (blocks until exit)
		if err := tui.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
			os.Exit(1)
		}
	}

	// Stop Technitium client
	if techClient != nil {
		techClient.Stop()
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
