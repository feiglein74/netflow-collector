# NetFlow Collector

Ein leichtgewichtiger NetFlow/IPFIX Collector mit interaktiver TUI-Oberfläche für Echtzeit-Netzwerkanalyse.

## Features

- **Multi-Protocol Support**: NetFlow v5, NetFlow v9, IPFIX (v10)
- **Interaktive TUI**: Echtzeit-Ansicht mit Sortierung, Filterung und Detail-Ansicht
- **Zwei-Seiten Layout**: F1 für Flow-Tabelle, F2 für Interface-Statistiken
- **Interface-Analyse**: Automatisches Subnet-Guessing für IPv4 und IPv6
- **IP-Detail-Ansicht**: Alle IPs pro Interface mit Live-Updates
- **Wireshark-Style Filter**: Komplexe Filterausdrücke mit `&&`, `||`, `!`, `()`, CIDR-Notation
- **Interface-Filter**: Filterung nach Interface-ID (`if=`, `inif=`, `outif=`)
- **DNS-Auflösung**: Asynchrone Reverse-DNS-Lookups mit Caching
- **Service-Erkennung**: Automatische Port-zu-Service Auflösung (170+ Services)
- **Persistente Filter-History**: Speicherung und Wiederverwendung von Filtern

## Installation

```bash
go build -o netflow-collector.exe ./cmd/collector
```

## Verwendung

```bash
# Standard TUI-Modus
./netflow-collector.exe

# Simple CLI ohne Interaktivität
./netflow-collector.exe -simple

# Eigener Port
./netflow-collector.exe -port 9995
```

### Command Line Flags

| Flag | Default | Beschreibung |
|------|---------|--------------|
| `-port` | 2055 | UDP Port für NetFlow-Empfang |
| `-simple` | false | Simple CLI statt interaktiver TUI |
| `-refresh` | 500ms | Display Refresh Rate |
| `-max-flows` | 100000 | Maximale Flows im Speicher |

## TUI Bedienung

### Seiten

| Taste | Seite | Beschreibung |
|-------|-------|--------------|
| `F1` | Flows | Flow-Tabelle mit allen empfangenen Flows |
| `F2` | Interfaces | Interface-Statistiken mit Subnet-Guessing |

### Tastenkürzel

**Navigation & Ansicht:**
- `↑/↓` - Flow/Interface auswählen
- `Enter` - Detail-Ansicht (Flow-Details oder IP-Liste pro Interface)
- `Space` - Pause/Resume (F1) oder IP markieren (F2 Detail)
- `?` - Hilfe ein/ausblenden
- `q` / `Ctrl+C` - Beenden

**Sortierung (F1):**
- `1` - Nach Zeit
- `2` - Nach Bytes
- `3` - Nach Packets
- `4` - Nach Source IP
- `5` - Nach Dest IP
- `6` - Nach Protocol/Service
- `r` - Sortierung umkehren

**Filter:**
- `f` - Filter-Eingabe aktivieren
- `c` - Filter löschen
- `n` - DNS-Auflösung toggle
- `v` - Service-Namen toggle
- `↑/↓` (im Filter) - Filter-History durchblättern
- `Tab` - Autocomplete-Vorschlag übernehmen
- `Enter` - Filter anwenden
- `Esc` - Autocomplete schließen

### Interface-Statistiken (F2)

Die Interface-Seite zeigt:
- **Interface-ID**: SNMP-Index des Interfaces
- **In/Out Flows**: Anzahl der Flows in/aus dem Interface
- **In/Out Traffic**: Bytes in/aus dem Interface
- **Subnet (IPv4)**: Automatisch erkanntes Subnetz aus privaten IPs
- **Subnet (IPv6)**: Bei IPv6-Traffic zweizeilig mit ULA/Link-Local

**Subnet-Guessing:**
- Analysiert private IPv4-Adressen (10.x, 172.16-31.x, 192.168.x)
- Erkennt IPv6 ULA (fd00::/8) und Link-Local (fe80::/10)
- Berechnet gemeinsames Prefix für Subnet-Erkennung
- Aktualisiert sich dynamisch bei neuen Flows

**IP-Detail-Ansicht (Enter auf Interface):**
- Zeigt alle erkannten IPs des Interfaces
- Sortiert nach Subnetz-Bereich, dann numerisch
- `Space` markiert IPs für Filter
- `Enter` wendet markierte IPs als Filter an
- Live-Updates während die Ansicht offen ist

### Filter-Syntax

Der Collector unterstützt Wireshark-ähnliche Filter mit voller Operator-Unterstützung:

```
# Einfache Filter
src=10.0.0.1
dst=192.168.1.0/24
port:443
proto=tcp

# CIDR-Notation für Subnetze
ip=10.0.0.0/8
src=192.168.0.0/16
dst=172.16.0.0/12

# Interface-Filter
if=4                    # In- oder Out-Interface
inif=2                  # Nur Input-Interface
outif=3                 # Nur Output-Interface

# Kombinierte Filter
if=4 && ip=192.168.0.0/16
inif=2 && proto=tcp

# Logische Operatoren
src=10.0.0.1 && dst=192.168.1.1
port:80 || port:443
!proto=udp

# Gruppierung mit Klammern
!(src=10.0.0.251 && port:53)
(proto=tcp || proto=udp) && ip=10.0.0.1

# Negation
ip!=10.0.0.251
service!=dns
```

**Filter-Felder:**

| Feld | Aliases | Beschreibung |
|------|---------|--------------|
| `src` | `srcip`, `source` | Source IP (CIDR supported) |
| `dst` | `dstip`, `dest` | Destination IP (CIDR supported) |
| `ip` | - | Source oder Destination IP (CIDR supported) |
| `srcport` | `sport` | Source Port |
| `dstport` | `dport` | Destination Port |
| `port` | - | Source oder Destination Port |
| `proto` | `protocol` | Protokoll (tcp/udp/icmp/6/17/1) |
| `service` | `svc` | Service-Name (http/https/dns/...) |
| `version` | `ver` | NetFlow Version (5/9/10) |
| `if` | `interface` | In- oder Out-Interface ID |
| `inif` | `inputif` | Input Interface ID |
| `outif` | `outputif` | Output Interface ID |

## Architektur

```
cmd/collector/main.go       Entry Point
internal/
  listener/udp.go           UDP Packet Receiver
  parser/
    parser.go               Version Detection, Template Cache
    netflow5.go             NetFlow v5 Parser
    netflow9.go             NetFlow v9 Parser
    ipfix.go                IPFIX Parser
  store/flowstore.go        In-Memory Storage, Filter Engine mit CIDR Support
  display/
    cli.go                  Simple Terminal Display
    tui.go                  Interactive TUI (tview) mit F1/F2 Seiten
  resolver/
    resolver.go             DNS Resolution mit Caching
    services.go             Port-zu-Service Mapping
pkg/types/flow.go           Flow Struct und Helpers
```

## Protocol Details

### NetFlow v5
- Festes Format: 24-Byte Header + 48-Byte Records
- Keine Templates, direkt parsbar
- Nur IPv4 Support

### NetFlow v9
- Template-basiert: Flowsets mit ID 0 definieren Templates
- Data Flowsets mit ID >= 256 referenzieren Templates
- IPv4 und IPv6 Support

### IPFIX (v10)
- Template Sets mit ID 2
- Options Template Sets mit ID 3
- Enterprise Bit Handling für vendor-spezifische Felder
- Variable-Length Fields Support

## Lizenz

MIT License - siehe [LICENSE](LICENSE)
