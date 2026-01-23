package types

import (
	"fmt"
	"net"
	"time"
)

// FlowVersion repräsentiert die NetFlow/IPFIX Version
type FlowVersion int

const (
	NetFlowV5 FlowVersion = 5
	NetFlowV9 FlowVersion = 9
	IPFIX     FlowVersion = 10
)

func (v FlowVersion) String() string {
	switch v {
	case NetFlowV5:
		return "NetFlow v5"
	case NetFlowV9:
		return "NetFlow v9"
	case IPFIX:
		return "IPFIX"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// Flow repräsentiert einen einzelnen Netzwerk-Flow-Datensatz
type Flow struct {
	Version      FlowVersion
	SrcAddr      net.IP
	DstAddr      net.IP
	SrcPort      uint16
	DstPort      uint16
	Protocol     uint8
	Bytes        uint64
	Packets      uint64
	StartTime    time.Time
	EndTime      time.Time
	TCPFlags     uint8
	SrcAS        uint32
	DstAS        uint32
	InputIf      uint16
	OutputIf     uint16
	ExporterIP   net.IP
	ReceivedAt   time.Time
	LastAccessed time.Time // LRU-Tracking - wann der Flow zuletzt angezeigt/abgefragt wurde
}

// ProtocolName gibt den lesbaren Protokollnamen zurück
func (f *Flow) ProtocolName() string {
	switch f.Protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("%d", f.Protocol)
	}
}

// TCPFlagsString gibt TCP-Flags als String zurück
func (f *Flow) TCPFlagsString() string {
	if f.Protocol != 6 {
		return "-"
	}
	flags := ""
	if f.TCPFlags&0x01 != 0 {
		flags += "F" // FIN
	}
	if f.TCPFlags&0x02 != 0 {
		flags += "S" // SYN
	}
	if f.TCPFlags&0x04 != 0 {
		flags += "R" // RST
	}
	if f.TCPFlags&0x08 != 0 {
		flags += "P" // PSH
	}
	if f.TCPFlags&0x10 != 0 {
		flags += "A" // ACK
	}
	if f.TCPFlags&0x20 != 0 {
		flags += "U" // URG
	}
	if flags == "" {
		flags = "."
	}
	return flags
}

// Duration gibt die Flow-Dauer zurück
func (f *Flow) Duration() time.Duration {
	return f.EndTime.Sub(f.StartTime)
}

// BytesPerSecond berechnet den Durchsatz
func (f *Flow) BytesPerSecond() float64 {
	d := f.Duration().Seconds()
	if d <= 0 {
		return 0
	}
	return float64(f.Bytes) / d
}

// FlowKey generiert einen eindeutigen Schlüssel für den Flow (für Aggregation)
func (f *Flow) FlowKey() string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		f.SrcAddr, f.SrcPort,
		f.DstAddr, f.DstPort,
		f.Protocol)
}

// ConversationKey generiert einen bidirektionalen Schlüssel (gleich für beide Richtungen)
func (f *Flow) ConversationKey() string {
	// Normalisieren: kleinere IP:Port zuerst
	src := fmt.Sprintf("%s:%d", f.SrcAddr, f.SrcPort)
	dst := fmt.Sprintf("%s:%d", f.DstAddr, f.DstPort)
	if src < dst {
		return fmt.Sprintf("%s-%s-%d", src, dst, f.Protocol)
	}
	return fmt.Sprintf("%s-%s-%d", dst, src, f.Protocol)
}

// Conversation repräsentiert einen bidirektionalen Flow (Anfrage + Antwort)
type Conversation struct {
	// Endpunkt A (die lexikografisch "kleinere" IP:Port)
	AddrA net.IP
	PortA uint16
	// Endpunkt B
	AddrB    net.IP
	PortB    uint16
	Protocol uint8

	// Vorwärtsrichtung (A -> B)
	BytesAtoB   uint64
	PacketsAtoB uint64
	FlowsAtoB   int

	// Rückwärtsrichtung (B -> A)
	BytesBtoA   uint64
	PacketsBtoA uint64
	FlowsBtoA   int

	// Aggregierte Zeitstempel
	FirstSeen time.Time
	LastSeen  time.Time

	// Für Anzeige
	InputIf    uint16
	OutputIf   uint16
	ExporterIP net.IP
}

// TotalBytes gibt die Gesamtbytes in beide Richtungen zurück
func (c *Conversation) TotalBytes() uint64 {
	return c.BytesAtoB + c.BytesBtoA
}

// TotalPackets gibt die Gesamtpakete in beide Richtungen zurück
func (c *Conversation) TotalPackets() uint64 {
	return c.PacketsAtoB + c.PacketsBtoA
}

// IsBidirectional gibt true zurück wenn Traffic in beide Richtungen existiert
func (c *Conversation) IsBidirectional() bool {
	return c.FlowsAtoB > 0 && c.FlowsBtoA > 0
}

// ProtocolName gibt den lesbaren Protokollnamen zurück
func (c *Conversation) ProtocolName() string {
	switch c.Protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("%d", c.Protocol)
	}
}

// Key gibt einen eindeutigen Bezeichner für diese Conversation zurück
func (c *Conversation) Key() string {
	return fmt.Sprintf("%s:%d-%s:%d-%d", c.AddrA, c.PortA, c.AddrB, c.PortB, c.Protocol)
}
