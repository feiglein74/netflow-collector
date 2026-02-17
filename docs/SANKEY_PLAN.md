# Sankey Diagramm Visualisierung - Implementierungsplan

## Übersicht

Zwei Komponenten:
1. **HTTP API im Collector** - Exponiert Flow-Daten als JSON
2. **Sankey-Tool** - Webserver mit D3.js Sankey-Diagramm

```
┌─────────────┐    JSON API     ┌─────────────┐    HTTP     ┌─────────┐
│  Collector  │ ──────────────> │ cmd/sankey  │ ──────────> │ Browser │
│  :8080/api  │                 │    :8081    │             │ (D3.js) │
└─────────────┘                 └─────────────┘             └─────────┘
```

## Neue Dateien

```
internal/
  api/
    server.go      # HTTP API Server für Collector
    handlers.go    # API Endpoints + Aggregations-Logik
    types.go       # JSON Response Structs

cmd/
  sankey/
    main.go        # CLI Entry Point
    static/
      index.html   # Frontend
      sankey.js    # D3.js Visualization
      style.css    # Styling
```

## Änderungen an bestehenden Dateien

- `cmd/collector/main.go` - Neues Flag `--api-port` (default 8080)

## API Endpoints

### GET `/api/v1/sankey`

Query-Parameter:
- `mode`: `ip-to-ip` | `ip-to-service`
- `filter`: Filter-Ausdruck (optional)
- `topN`: Limit (default 50)

Response:
```json
{
  "mode": "ip-to-ip",
  "nodes": [
    {"id": "192.168.1.1", "type": "source", "label": "192.168.1.1"}
  ],
  "links": [
    {"source": "192.168.1.1", "target": "8.8.8.8", "value": 15234}
  ]
}
```

### GET `/api/v1/flows`

Raw flows mit Filter/Limit

### GET `/api/v1/stats`

Flow-Store Statistiken

## CLI Flags

### Collector
```bash
./netflow-collector.exe --api-port 8080  # API aktivieren
```

### Sankey-Tool
```bash
./sankey.exe                              # Default: collector localhost:8080
./sankey.exe --collector http://10.0.0.1:8080
./sankey.exe --port 8081                  # Web-UI Port
./sankey.exe --mode ip-to-service         # Start-Modus
./sankey.exe --filter "proto=tcp"         # Initial-Filter
./sankey.exe --top 30                     # Top-N Limit
```

## Implementierungsschritte

### Phase 1: API (internal/api/)
1. `types.go` - SankeyNode, SankeyLink, SankeyData Structs
2. `handlers.go` - aggregateIPtoIP(), aggregateIPtoService()
3. `server.go` - HTTP Server mit CORS
4. `cmd/collector/main.go` - --api-port Flag, Server-Start

### Phase 2: Sankey-Tool (cmd/sankey/)
1. `main.go` - Cobra CLI, Webserver, Proxy zu Collector-API
2. Statische Dateien embedden (go:embed)

### Phase 3: Frontend
1. `index.html` - Controls (Mode-Toggle, Filter, TopN, Refresh)
2. `sankey.js` - D3.js Sankey mit Tooltips
3. `style.css` - Dark Theme passend zur TUI

## Frontend Features

- Toggle: IP→IP / IP→Service
- Filter-Eingabe (Wireshark-Syntax)
- Top-N Slider (10-200)
- Auto-Refresh (optional, 10s)
- Tooltips: Bytes, Packets, Protocol
- Farbcodierung: Internal (grün) vs External (blau)

## Abhängigkeiten

Keine neuen Go-Dependencies. Frontend via CDN:
- D3.js v7
- d3-sankey Plugin

## Verifikation

1. Collector starten mit `--api-port 8080`
2. `curl http://localhost:8080/api/v1/stats` prüfen
3. Sankey-Tool starten: `./sankey.exe`
4. Browser öffnen: `http://localhost:8081`
5. Mode-Toggle testen
6. Filter testen (z.B. `proto=tcp`)
