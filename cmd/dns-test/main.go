package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	server := flag.String("server", "", "Technitium DNS server URL (e.g., http://192.168.1.1:5380)")
	token := flag.String("token", "", "API token")
	appName := flag.String("app", "Query Logs (Sqlite)", "DNS App name")
	classPath := flag.String("class", "QueryLogsSqlite.App", "DNS App class path")
	flag.Parse()

	if *server == "" || *token == "" {
		fmt.Println("Usage: dns-test -server http://IP:5380 -token YOUR_TOKEN")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Test 1: Check session
	fmt.Println("=== Test 1: Checking API connection ===")
	sessionURL := fmt.Sprintf("%s/api/user/session/get?token=%s", *server, *token)
	fmt.Printf("URL: %s\n", sessionURL)

	resp, err := client.Get(sessionURL)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var sessionResp map[string]interface{}
	json.Unmarshal(body, &sessionResp)
	prettyPrint("Session Response", sessionResp)

	if sessionResp["status"] != "ok" {
		fmt.Printf("\nERROR: API returned status '%v'\n", sessionResp["status"])
		if msg, ok := sessionResp["errorMessage"]; ok {
			fmt.Printf("Error message: %v\n", msg)
		}
		os.Exit(1)
	}
	fmt.Println("✓ API connection OK\n")

	// Test 2: List installed apps
	fmt.Println("=== Test 2: Listing installed DNS Apps ===")
	appsURL := fmt.Sprintf("%s/api/apps/list?token=%s", *server, *token)
	fmt.Printf("URL: %s\n", appsURL)

	resp, err = client.Get(appsURL)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		var appsResp map[string]interface{}
		json.Unmarshal(body, &appsResp)
		prettyPrint("Apps Response", appsResp)
	}
	fmt.Println()

	// Test 3: Query logs
	fmt.Println("=== Test 3: Fetching Query Logs ===")
	end := time.Now()
	start := end.Add(-5 * time.Minute)

	params := url.Values{}
	params.Set("token", *token)
	params.Set("name", *appName)
	params.Set("classPath", *classPath)
	params.Set("start", start.UTC().Format(time.RFC3339))
	params.Set("end", end.UTC().Format(time.RFC3339))
	params.Set("entriesPerPage", "20")
	params.Set("descendingOrder", "true")

	logsURL := fmt.Sprintf("%s/api/logs/query?%s", *server, params.Encode())
	fmt.Printf("URL: %s\n\n", logsURL)

	resp, err = client.Get(logsURL)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Raw response (first 2000 chars):\n%s\n\n", truncate(string(body), 2000))

	var logsResp map[string]interface{}
	if err := json.Unmarshal(body, &logsResp); err != nil {
		fmt.Printf("ERROR parsing JSON: %v\n", err)
		os.Exit(1)
	}

	prettyPrint("Logs Response", logsResp)

	if logsResp["status"] != "ok" {
		fmt.Printf("\nERROR: Query logs failed with status '%v'\n", logsResp["status"])
		if msg, ok := logsResp["errorMessage"]; ok {
			fmt.Printf("Error message: %v\n", msg)
		}
	} else {
		fmt.Println("\n✓ Query logs OK")

		// Count entries
		if response, ok := logsResp["response"].(map[string]interface{}); ok {
			if entries, ok := response["entries"].([]interface{}); ok {
				fmt.Printf("Found %d log entries\n", len(entries))

				// Show first few entries
				for i, e := range entries {
					if i >= 5 {
						fmt.Printf("... and %d more\n", len(entries)-5)
						break
					}
					if entry, ok := e.(map[string]interface{}); ok {
						fmt.Printf("\n  Entry %d:\n", i+1)
						fmt.Printf("    qname: %v\n", entry["qname"])
						fmt.Printf("    qtype: %v\n", entry["qtype"])
						fmt.Printf("    answer: %v\n", truncate(fmt.Sprintf("%v", entry["answer"]), 100))
					}
				}
			}
		}
	}
}

func prettyPrint(title string, data interface{}) {
	out, _ := json.MarshalIndent(data, "", "  ")
	fmt.Printf("%s:\n%s\n", title, truncate(string(out), 1500))
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
