# Design Principles

Dieses Dokument beschreibt die Architektur- und Design-Entscheidungen des NetFlow Collectors.

## Kernprinzipien

### 1. Einfachheit vor Features
- Single Binary ohne externe Abhängigkeiten zur Laufzeit
- Keine Konfigurationsdateien erforderlich - CLI-Flags reichen
- In-Memory Storage statt komplexer Datenbank-Setups

### 2. Responsiveness
- Async DNS-Lookups blockieren nie die UI
- Separate Goroutine für Packet-Verarbeitung
- Kurze Refresh-Intervalle (500ms default)

### 3. Standard-Compliance
- NetFlow v5 nach RFC (nicht offiziell, aber de-facto Standard)
- NetFlow v9 nach RFC 3954
- IPFIX nach RFC 7011

## Architektur-Entscheidungen

### Warum In-Memory statt Datenbank?

**Pro:**
- Null Setup-Aufwand
- Minimale Latenz bei Abfragen
- Einfache Deployment (Single Binary)

**Contra:**
- Limitierte History
- Datenverlust bei Crash
- Speicherbegrenzung

**Entscheidung:** Für Echtzeit-Monitoring ist In-Memory optimal. Persistenz kann später als optionales Feature ergänzt werden.

### Warum Template-basiertes Parsing?

NetFlow v9 und IPFIX sind template-basiert. Wir cachen Templates pro:
- Source IP + Port
- Observation Domain ID (für IPFIX)

Templates werden bei Empfang gecached und bei passenden Data Records angewandt. Flows ohne bekanntes Template werden verworfen (silent drop) - das ist Standard-konform.

### Warum Expression Tree für Filter?

Ursprünglich war der Filter einfach (key=value). Mit wachsenden Anforderungen (AND, OR, NOT, Klammern) wurde ein vollständiger Expression Tree Parser implementiert:

```
Filter: !(src=10.0.0.1 && port:53)

Tree:
  NOT
   |
  AND
  / \
src  port
```

**Vorteile:**
- Beliebig komplexe Ausdrücke
- Korrekte Operator-Precedenz (NOT > AND > OR)
- Erweiterbar für neue Operatoren

### Warum tview für TUI?

**Alternativen evaluiert:**
- bubbletea: Gut, aber Elm-Architecture Overhead
- termui: Weniger aktiv gepflegt
- gocui: Weniger Features

**tview Vorteile:**
- Aktive Entwicklung
- Umfangreiche Widget-Bibliothek
- Gute Dokumentation
- Mouse-Support

## Code-Organisation

### Package-Struktur

```
cmd/           - Ausführbare Programme
internal/      - Private Packages (nicht importierbar)
pkg/           - Öffentliche Packages (importierbar)
```

### Separation of Concerns

- **listener**: Nur UDP-Empfang, keine Protokoll-Logik
- **parser**: Nur Protokoll-Parsing, keine Speicherung
- **store**: Nur Speicherung und Filterung, kein I/O
- **display**: Nur Anzeige, keine Datenverarbeitung
- **resolver**: Nur DNS/Service-Auflösung

### Thread Safety

- Flow Store nutzt `sync.RWMutex` für concurrent access
- DNS Cache ist ebenfalls mutex-geschützt
- Template Cache pro Parser-Instanz (keine shared state zwischen Parsern)

## Performance-Überlegungen

### Memory Management

- Flows werden nach `retention` Period gelöscht
- Maximale Flow-Anzahl (`max-flows`) begrenzt Speicherverbrauch
- Älteste Flows werden bei Überlauf entfernt

### UI Performance

- High Water Mark für Spaltenbreiten vermeidet ständiges Neuberechnen
- Gefilterte Flows werden gecached bis Filter/Daten sich ändern
- Statistiken werden inkrementell aktualisiert

## Erweiterbarkeit

### Neue Protokoll-Versionen

1. Neuer Parser in `internal/parser/`
2. Version-Detection in `parser.go` erweitern
3. Flow-Typ in `pkg/types/flow.go` falls nötig erweitern

### Neue Filter-Felder

1. Case in `matchCondition()` in `store/flowstore.go` hinzufügen
2. Dokumentation in CLAUDE.md und README.md aktualisieren

### Neue Display-Modi

1. Neues Package in `internal/display/`
2. Interface in `main.go` nutzen (aktuell: `Start()` oder `Run()`)
