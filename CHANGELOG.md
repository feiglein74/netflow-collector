# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/).

## [0.1.0] - 2025-11-29

### Hinzugefügt

- **Core Features**
  - NetFlow v5 Parser mit fixem 48-Byte Record Format
  - NetFlow v9 Parser mit Template-Support
  - IPFIX (v10) Parser mit Enterprise Bit Handling
  - UDP Listener für NetFlow-Empfang

- **TUI Interface**
  - Interaktive Terminal UI mit tview
  - Echtzeit Flow-Tabelle mit automatischer Aktualisierung
  - Sortierung nach allen Spalten (Zeit, Bytes, Packets, IPs, Protocol)
  - Flow Detail-Ansicht mit Enter-Taste
  - Maus-Support für Navigation

- **Filter-Engine**
  - Wireshark-ähnliche Filter-Syntax
  - Logische Operatoren: `&&`, `||`, `!`
  - Klammer-Support für komplexe Ausdrücke
  - Negations-Operator `!=`
  - Filter-Felder: src, dst, host, port, proto, service, version
  - CIDR-Notation für IP-Bereiche
  - Persistente Filter-History (~/.netflow-filter-history)

- **DNS & Service Resolution**
  - Asynchrone DNS-Auflösung mit Cache
  - 170+ vordefinierte Service-Namen
  - Separate TCP/UDP Service-Mappings
  - Toggle für DNS/Service-Anzeige

- **Display Features**
  - Stabile Spaltenbreiten (High Water Mark Algorithmus)
  - Gefilterte Traffic-Statistiken
  - Farbcodierte Filter-Status Anzeige
  - Simple CLI-Modus als Alternative

### Technische Details

- Go 1.25+ mit Modules
- Abhängigkeiten: tview, tcell
- Template-Cache pro Source/Observation-Domain
- Thread-safe Flow Store mit RWMutex
