# TODO

## Geplante Features

### Hohe Priorität

- [ ] **Export-Funktionen**
  - CSV-Export der aktuellen Ansicht
  - JSON-Export für Weiterverarbeitung
  - PCAP-ähnlicher Flow-Export

- [ ] **Erweiterte Statistiken**
  - Top-Talker Ansicht
  - Traffic-Verteilung nach Protokoll
  - Zeitbasierte Traffic-Graphen

### Mittlere Priorität

- [ ] **Firewall-Regel Korrelation**
  - Generisches Regelwerk-Format (herstellerunabhängig)
  - First-Match Logik wie echte Firewall
  - Regel-Spalte in Flow-Tabelle zeigt matchende Regel
  - Später: Importer für Cisco ACL, iptables, Palo Alto, Fortinet, Ubiquiti/UniFi, etc.

- [ ] **Persistenz**
  - SQLite Backend für historische Daten
  - Flow-Archivierung mit Rotation
  - Replay-Funktion für gespeicherte Flows

- [ ] **Netzwerk-Features**
  - Multi-Port Listener
  - TLS-Support für IPFIX
  - Flow-Forwarding an andere Collector

- [ ] **UI Verbesserungen**
  - Farbige Protokoll-Hervorhebung
  - Customizable Spalten
  - Bookmarks für häufige Filter

### Niedrige Priorität

- [ ] **Integration**
  - REST API für externe Abfragen
  - Prometheus Metrics Endpoint
  - Webhook-Benachrichtigungen

- [ ] **Erweiterte Analyse**
  - Anomalie-Erkennung
  - Baseline-Vergleich
  - GeoIP-Integration

## Technische Schulden / Regel-Abweichungen

Gefunden bei Prüfung gegen CLAUDE.md (2026-01-23):

- [x] **`.gitattributes` fehlt** - Behoben (2026-01-23)
- [x] **Lint-Fehler** - `cmd/dns-test/main.go:54` - Behoben (2026-01-23)
- [ ] **Code-Kommentare auf Englisch** - Teilweise behoben, noch ausstehend:
  - [x] `pkg/types/flow.go`
  - [x] `cmd/collector/main.go`
  - [x] `cmd/sankey/main.go`
  - [x] `internal/api/types.go`
  - [x] `internal/api/server.go`
  - [ ] `internal/api/handlers.go`
  - [ ] `internal/store/flowstore.go`
  - [ ] `internal/display/*.go` (7 Dateien)
  - [ ] `internal/parser/*.go` (4 Dateien)
  - [ ] `internal/listener/udp.go`
  - [ ] `internal/resolver/*.go` (3 Dateien)
  - [ ] `cmd/dns-test/main.go`

## Bekannte Einschränkungen

- Variable-Length IPFIX Felder werden noch nicht vollständig unterstützt
- Keine IPv6 Reverse-DNS Auflösung optimiert
- Template-Cache wird nicht persistiert (geht bei Neustart verloren)

## Abgeschlossene Features

- [x] NetFlow v5/v9/IPFIX Parsing
- [x] Interaktive TUI mit tview
- [x] Wireshark-Style Filter mit Klammern
- [x] DNS-Auflösung mit Cache
- [x] Service-Name Auflösung
- [x] Filter-History mit Persistenz
- [x] Flow Detail-Ansicht
- [x] Maus-Support
- [x] != Operator für Filter
- [x] Sankey Zeitraum-Filter (1m, 5m, 15m, 30m, 1h, 6h, 24h, All)
