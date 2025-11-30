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
