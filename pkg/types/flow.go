package types

import (
	"fmt"
	"net"
	"time"
)

// FlowVersion represents the NetFlow/IPFIX version
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

// Flow represents a single network flow record
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
	LastAccessed time.Time // LRU tracking - when flow was last viewed/queried
}

// ProtocolName returns the human-readable protocol name
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

// TCPFlagsString returns TCP flags as string
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

// Duration returns the flow duration
func (f *Flow) Duration() time.Duration {
	return f.EndTime.Sub(f.StartTime)
}

// BytesPerSecond calculates the throughput
func (f *Flow) BytesPerSecond() float64 {
	d := f.Duration().Seconds()
	if d <= 0 {
		return 0
	}
	return float64(f.Bytes) / d
}

// FlowKey generates a unique key for the flow (for aggregation)
func (f *Flow) FlowKey() string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		f.SrcAddr, f.SrcPort,
		f.DstAddr, f.DstPort,
		f.Protocol)
}

// ConversationKey generates a bidirectional key (same for both directions)
func (f *Flow) ConversationKey() string {
	// Normalize: smaller IP:port first
	src := fmt.Sprintf("%s:%d", f.SrcAddr, f.SrcPort)
	dst := fmt.Sprintf("%s:%d", f.DstAddr, f.DstPort)
	if src < dst {
		return fmt.Sprintf("%s-%s-%d", src, dst, f.Protocol)
	}
	return fmt.Sprintf("%s-%s-%d", dst, src, f.Protocol)
}

// Conversation represents a bidirectional flow (request + response)
type Conversation struct {
	// Endpoint A (the "smaller" IP:port lexicographically)
	AddrA    net.IP
	PortA    uint16
	// Endpoint B
	AddrB    net.IP
	PortB    uint16
	Protocol uint8

	// Forward direction (A -> B)
	BytesAtoB   uint64
	PacketsAtoB uint64
	FlowsAtoB   int

	// Reverse direction (B -> A)
	BytesBtoA   uint64
	PacketsBtoA uint64
	FlowsBtoA   int

	// Aggregated timing
	FirstSeen time.Time
	LastSeen  time.Time

	// For display
	InputIf    uint16
	OutputIf   uint16
	ExporterIP net.IP
}

// TotalBytes returns total bytes in both directions
func (c *Conversation) TotalBytes() uint64 {
	return c.BytesAtoB + c.BytesBtoA
}

// TotalPackets returns total packets in both directions
func (c *Conversation) TotalPackets() uint64 {
	return c.PacketsAtoB + c.PacketsBtoA
}

// IsBidirectional returns true if traffic exists in both directions
func (c *Conversation) IsBidirectional() bool {
	return c.FlowsAtoB > 0 && c.FlowsBtoA > 0
}

// ProtocolName returns the human-readable protocol name
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

// Key returns a unique identifier for this conversation
func (c *Conversation) Key() string {
	return fmt.Sprintf("%s:%d-%s:%d-%d", c.AddrA, c.PortA, c.AddrB, c.PortB, c.Protocol)
}
