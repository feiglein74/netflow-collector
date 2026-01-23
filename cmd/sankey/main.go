package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

//go:embed static/*
var staticFiles embed.FS

var (
	collectorURL string
	port         int
	mode         string
	filter       string
	topN         int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sankey",
		Short: "Sankey-Diagramm-Visualisierung für NetFlow-Daten",
		Long: `Ein webbasiertes Sankey-Diagramm-Visualisierungs-Tool für NetFlow-Daten.

Verbindet sich mit der API eines NetFlow Collectors und zeigt Traffic-Flows
als interaktives Sankey-Diagramm im Browser an.

Beispiel:
  sankey --collector http://localhost:8080 --port 8081`,
		Run: runServer,
	}

	rootCmd.Flags().StringVar(&collectorURL, "collector", "http://localhost:8080", "NetFlow Collector API URL")
	rootCmd.Flags().IntVar(&port, "port", 8081, "Web UI Port")
	rootCmd.Flags().StringVar(&mode, "mode", "ip-to-ip", "Initial-Modus: ip-to-ip oder ip-to-service")
	rootCmd.Flags().StringVar(&filter, "filter", "", "Initialer Filter-Ausdruck")
	rootCmd.Flags().IntVar(&topN, "top", 50, "Initiales Top-N Limit")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	mux := http.NewServeMux()

	// API-Anfragen an Collector weiterleiten
	mux.HandleFunc("/api/", proxyHandler)

	// Config-Endpoint bereitstellen
	mux.HandleFunc("/config", configHandler)

	// Statische Dateien bereitstellen
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fehler beim Zugriff auf statische Dateien: %v\n", err)
		os.Exit(1)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	fmt.Printf("Sankey Visualisierungs-Server startet...\n")
	fmt.Printf("  Collector API: %s\n", collectorURL)
	fmt.Printf("  Web UI:        http://localhost:%d\n", port)
	fmt.Printf("  Initial-Modus: %s\n", mode)
	if filter != "" {
		fmt.Printf("  Initial-Filter: %s\n", filter)
	}
	fmt.Printf("\nDrücke Strg+C zum Stoppen\n")

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Server-Fehler: %v\n", err)
		os.Exit(1)
	}
}

// proxyHandler leitet API-Anfragen an den Collector weiter
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Ziel-URL erstellen
	targetURL := collectorURL + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Proxy-Request erstellen
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, "Fehler beim Erstellen des Proxy-Requests", http.StatusInternalServerError)
		return
	}

	// Header weiterleiten
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Request ausführen
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Collector API Fehler: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Response-Header kopieren
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// CORS-Header hinzufügen
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// configHandler gibt die initiale Konfiguration zurück
func configHandler(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"collectorURL": collectorURL,
		"mode":         mode,
		"filter":       filter,
		"topN":         topN,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}
