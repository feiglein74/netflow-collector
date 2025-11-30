package parser

import (
	"encoding/binary"
	"fmt"
	"net"

	"netflow-collector/pkg/types"
)

// Parser can parse NetFlow/IPFIX packets
type Parser struct {
	// Template cache for NetFlow v9 and IPFIX
	v9Templates   map[uint32]map[uint16]*Template
	ipfixTemplates map[uint32]map[uint16]*Template
}

// Template represents a NetFlow v9 or IPFIX template
type Template struct {
	ID        uint16
	FieldDefs []FieldDef
	Length    int
}

// FieldDef defines a field in a template
type FieldDef struct {
	Type   uint16
	Length uint16
}

// New creates a new parser
func New() *Parser {
	return &Parser{
		v9Templates:    make(map[uint32]map[uint16]*Template),
		ipfixTemplates: make(map[uint32]map[uint16]*Template),
	}
}

// Parse parses a NetFlow/IPFIX packet and returns flows
func (p *Parser) Parse(data []byte, sourceAddr *net.UDPAddr) ([]types.Flow, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	version := binary.BigEndian.Uint16(data[0:2])

	switch version {
	case 5:
		return p.parseNetFlowV5(data, sourceAddr)
	case 9:
		return p.parseNetFlowV9(data, sourceAddr)
	case 10:
		return p.parseIPFIX(data, sourceAddr)
	default:
		return nil, fmt.Errorf("unsupported NetFlow version: %d", version)
	}
}

// GetVersion returns the version from packet data without full parsing
func GetVersion(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("packet too short")
	}
	return binary.BigEndian.Uint16(data[0:2]), nil
}
