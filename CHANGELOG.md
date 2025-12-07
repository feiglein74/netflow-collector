# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/).

## [0.2.0] - 2025-11-30

### Hinzugefügt

- **Interface Statistics (F2)**
  - Neue Seite mit Statistiken pro Interface
  - Subnet-Erkennung aus privaten IPs (10.x, 172.16-31.x, 192.168.x)
  - IPv6 Support für ULA (fd00::/8) und Link-Local (fe80::/10)
  - Zwei-Zeilen-Anzeige wenn IPv6 vorhanden
  - Separate Spalten für interne (Int) und externe (Ext) IPs

- **IP Detail View**
  - Modal mit allen IPs eines Interface (Enter auf Interface)
  - Live-Updates während Modal geöffnet
  - Space zum Markieren, Enter zum Filtern
  - DNS-Auflösung für alle IPs mit Cache-Lookup
  - Typ-Anzeige (int/ext) mit Farbcodierung
  - Sortierung: Private IPs zuerst, dann Public

- **Hybrid Eviction System**
  - TopK-Protection für "Elephant Flows" (größte Flows nach Bytes)
  - LRU-Protection für kürzlich angesehene Flows
  - FIFO-Fallback für normale Flows
  - Neue CLI-Flags: `-topk-percent`, `-lru-window`
  - Eviction-Statistiken in TUI und beim Beenden

- **Filter-Erweiterungen**
  - Interface-Filter: `if=`, `inif=`, `outif=`
  - CIDR-Notation: `ip=192.168.0.0/24`

- **UI Verbesserungen**
  - Custom Autocomplete-Dropdown (ersetzt tview built-in)
  - Pfeiltasten-Navigation durch Vorschläge
  - Tab/Enter akzeptiert Auswahl, Esc schließt
  - Dropdown überlagert Tabelle statt sie zu verschieben
  - Locale-aware Zahlenformatierung (Deutsch: 1.234,5)

### Geändert

- Flow Detail View markiert Flow als "accessed" für LRU-Protection
- Interface Table hat jetzt Int/Ext Spalten statt nur IPs-Spalte
- max-flows Default korrigiert auf 100.000

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
