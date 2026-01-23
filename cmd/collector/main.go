package main

import (
	"fmt"
	"os"
	"time"

	"netflow-collector/internal/api"
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
	apiPort     int
	debugFlows  bool

	// Technitium DNS Flags
	dnsServer   string
	dnsToken    string
	dnsAppName  string
	dnsPollRate time.Duration
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netflow-collector",
		Short: "NetFlow/IPFIX Collector mit interaktiver TUI",
		Long: `Ein performanter NetFlow/IPFIX Collector der unterstützt:
  - NetFlow v5 (festes Format)
  - NetFlow v9 (Template-basiert)
  - IPFIX v10 (Template-basiert)

Bietet interaktive TUI mit Flow-Tabelle, Sortierung, Filterung,
DNS-Auflösung und Service-Namen-Mapping.`,
		Run: runCollector,
	}

	// Flags definieren
	rootCmd.Flags().IntVarP(&port, "port", "p", 2055, "UDP Port zum Lauschen")
	rootCmd.Flags().IntVarP(&maxFlows, "max-flows", "m", 100000, "Maximale Flows im Speicher")
	rootCmd.Flags().DurationVarP(&refreshRate, "refresh", "r", 500*time.Millisecond, "Display-Aktualisierungsrate")
	rootCmd.Flags().BoolVarP(&simple, "simple", "s", false, "Simple CLI statt interaktiver TUI verwenden")
	rootCmd.Flags().Float64Var(&topKPercent, "topk-percent", 1.0, "Prozent der max-flows die als Elephant-Flows geschützt werden (1.0 = 1%)")
	rootCmd.Flags().DurationVar(&lruWindow, "lru-window", 5*time.Minute, "Kürzlich angesehene Flows für diese Dauer schützen")
	rootCmd.Flags().IntVar(&prefixLen, "prefix-len", 56, "IPv6 Präfixlänge für eigene Netzwerk-Erkennung (48, 56, 60, 64)")

	// Technitium DNS Integration Flags
	rootCmd.Flags().StringVar(&dnsServer, "dns-server", "", "Technitium DNS Server URL (z.B. http://192.168.1.1:5380)")
	rootCmd.Flags().StringVar(&dnsToken, "dns-token", "", "Technitium DNS API Token")
	rootCmd.Flags().StringVar(&dnsAppName, "dns-app", "Query Logs (Sqlite)", "Technitium DNS App-Name für Query Logs")
	rootCmd.Flags().DurationVar(&dnsPollRate, "dns-poll", 5*time.Second, "Wie oft Technitium nach neuen DNS-Queries abgefragt wird")

	// API Server Flag
	rootCmd.Flags().IntVar(&apiPort, "api-port", 0, "HTTP API Server auf diesem Port aktivieren (0 = deaktiviert)")

	// Debug Flag
	rootCmd.Flags().BoolVar(&debugFlows, "debug-flows", false, "Alle eingehenden Flows auf stderr loggen")

	// Completion-Befehl hinzufügen
	rootCmd.AddCommand(&cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Shell-Completion-Skript generieren",
		Long: `Generiert Shell-Completion-Skript für die angegebene Shell.

PowerShell:
  netflow-collector completion powershell | Out-String | Invoke-Expression

  Für jede neue Sitzung laden, Ausgabe zum Profil hinzufügen:
  netflow-collector completion powershell >> $PROFILE

Bash:
  source <(netflow-collector completion bash)

  Für jede neue Sitzung laden (Linux):
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
	// Eviction-Konfiguration erstellen
	evictionConfig := store.EvictionConfig{
		TopKPercent: topKPercent,
		LRUWindow:   lruWindow,
	}

	// Komponenten erstellen
	udpListener := listener.New(port)
	flowParser := parser.New()
	flowStore := store.NewWithConfig(maxFlows, evictionConfig)

	// UDP Listener starten
	if err := udpListener.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Fehler beim Starten des Listeners: %v\n", err)
		os.Exit(1)
	}

	// Pakete im Hintergrund verarbeiten
	go func() {
		for packet := range udpListener.Packets() {
			flows, err := flowParser.Parse(packet.Data, packet.SourceAddr)
			if err != nil {
				if debugFlows {
					fmt.Fprintf(os.Stderr, "[DEBUG] Parse error from %s: %v\n", packet.SourceAddr, err)
				}
				continue
			}
			if debugFlows {
				for _, f := range flows {
					fmt.Fprintf(os.Stderr, "[DEBUG] Flow: %s:%d -> %s:%d proto=%s bytes=%d pkts=%d if=%d->%d\n",
						f.SrcAddr, f.SrcPort, f.DstAddr, f.DstPort, f.ProtocolName(),
						f.Bytes, f.Packets, f.InputIf, f.OutputIf)
				}
			}
			flowStore.Add(flows)
		}
	}()

	// Zentraler DNS-Resolver (wird von API und TUI geteilt)
	dnsResolver := resolver.New()

	// Technitium DNS Client (für DNS-Anreicherung)
	var techClient *resolver.TechnitiumClient

	// Technitium DNS Integration starten falls konfiguriert
	if dnsServer != "" && dnsToken != "" {
		techClient = resolver.NewTechnitiumClient(resolver.TechnitiumConfig{
			ServerURL:    dnsServer,
			Token:        dnsToken,
			AppName:      dnsAppName,
			PollInterval: dnsPollRate,
		}, dnsResolver)

		if err := techClient.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Warnung: Fehler beim Starten des Technitium DNS Clients: %v\n", err)
		}
	}

	// API Server starten falls Port konfiguriert
	var apiServer *api.Server
	if apiPort > 0 {
		apiServer = api.NewServerWithResolver(flowStore, apiPort, dnsResolver)
		if err := apiServer.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Fehler beim Starten des API Servers: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("API Server gestartet auf http://localhost:%d\n", apiPort)
	}

	if simple {
		// Simple CLI Modus
		cli := display.New(flowStore, refreshRate)
		fmt.Printf("NetFlow/IPFIX Collector gestartet auf UDP Port %d (Simple Modus)\n", port)
		fmt.Println("Unterstützte Versionen: NetFlow v5, v9, IPFIX (v10)")
		fmt.Println("Drücke Strg+C zum Beenden")
		fmt.Println()

		// Simple Display im Vordergrund ausführen
		cli.Start()
	} else {
		// Interaktiver TUI Modus (verwendet den gleichen Resolver)
		tui := display.NewTUIWithResolver(flowStore, refreshRate, prefixLen, dnsResolver)

		// TUI ausführen (blockiert bis Beenden)
		if err := tui.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Fehler beim Ausführen der TUI: %v\n", err)
			os.Exit(1)
		}
	}

	// Technitium Client stoppen
	if techClient != nil {
		techClient.Stop()
	}

	// API Server stoppen
	if apiServer != nil {
		apiServer.Stop()
	}

	// Aufräumen
	udpListener.Stop()

	// Endstatistiken ausgeben
	stats := flowStore.GetStats()
	evictStats := flowStore.GetEvictionStats()
	fmt.Printf("\nEndstatistiken:\n")
	fmt.Printf("  Gesamt Flows: %d\n", stats.TotalFlows)
	fmt.Printf("  Gesamt Bytes: %d\n", stats.TotalBytes)
	fmt.Printf("  Gesamt Pakete: %d\n", stats.TotalPackets)
	fmt.Printf("  NetFlow v5: %d\n", stats.V5Flows)
	fmt.Printf("  NetFlow v9: %d\n", stats.V9Flows)
	fmt.Printf("  IPFIX: %d\n", stats.IPFIXFlows)
	if evictStats.TotalEvicted > 0 {
		fmt.Printf("\nEviction-Statistiken:\n")
		fmt.Printf("  Gesamt Entfernt: %d\n", evictStats.TotalEvicted)
		fmt.Printf("  TopK Geschützt: %d\n", evictStats.TopKProtected)
		fmt.Printf("  LRU Geschützt: %d\n", evictStats.LRUProtected)
	}
}
