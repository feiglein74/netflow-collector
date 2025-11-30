package parser

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"netflow-collector/pkg/types"
)

const (
	netflowV9HeaderSize  = 20
	netflowV9FlowsetHdrSize = 4
)

// NetFlow v9 field type IDs
const (
	NF9_IN_BYTES          = 1
	NF9_IN_PKTS           = 2
	NF9_PROTOCOL          = 4
	NF9_SRC_TOS           = 5
	NF9_TCP_FLAGS         = 6
	NF9_L4_SRC_PORT       = 7
	NF9_IPV4_SRC_ADDR     = 8
	NF9_SRC_MASK          = 9
	NF9_INPUT_SNMP        = 10
	NF9_L4_DST_PORT       = 11
	NF9_IPV4_DST_ADDR     = 12
	NF9_DST_MASK          = 13
	NF9_OUTPUT_SNMP       = 14
	NF9_IPV4_NEXT_HOP     = 15
	NF9_SRC_AS            = 16
	NF9_DST_AS            = 17
	NF9_LAST_SWITCHED     = 21
	NF9_FIRST_SWITCHED    = 22
	NF9_IPV6_SRC_ADDR     = 27
	NF9_IPV6_DST_ADDR     = 28
	NF9_IPV6_FLOW_LABEL   = 31
	NF9_ICMP_TYPE         = 32
	NF9_DIRECTION         = 61
	NF9_IPV6_NEXT_HOP     = 62
)

// NetFlow v9 Header:
// Bytes 0-1:   Version (9)
// Bytes 2-3:   Count (number of FlowSets)
// Bytes 4-7:   SysUptime
// Bytes 8-11:  Unix Secs
// Bytes 12-15: Sequence Number
// Bytes 16-19: Source ID

func (p *Parser) parseNetFlowV9(data []byte, sourceAddr *net.UDPAddr) ([]types.Flow, error) {
	if len(data) < netflowV9HeaderSize {
		return nil, fmt.Errorf("NetFlow v9 packet too short for header: %d bytes", len(data))
	}

	// Parse header
	count := binary.BigEndian.Uint16(data[2:4])
	sysUptime := binary.BigEndian.Uint32(data[4:8])
	unixSecs := binary.BigEndian.Uint32(data[8:12])
	sourceID := binary.BigEndian.Uint32(data[16:20])

	// Calculate boot time
	baseTime := time.Unix(int64(unixSecs), 0)
	bootTime := baseTime.Add(-time.Duration(sysUptime) * time.Millisecond)

	// Ensure template map exists for this source
	if p.v9Templates[sourceID] == nil {
		p.v9Templates[sourceID] = make(map[uint16]*Template)
	}

	var flows []types.Flow
	offset := netflowV9HeaderSize

	// Process FlowSets
	for i := 0; i < int(count) && offset+netflowV9FlowsetHdrSize <= len(data); i++ {
		flowsetID := binary.BigEndian.Uint16(data[offset:])
		flowsetLen := binary.BigEndian.Uint16(data[offset+2:])

		if flowsetLen < 4 || offset+int(flowsetLen) > len(data) {
			break
		}

		flowsetData := data[offset+4 : offset+int(flowsetLen)]

		switch {
		case flowsetID == 0:
			// Template FlowSet
			p.parseV9Templates(flowsetData, sourceID)
		case flowsetID == 1:
			// Options Template FlowSet (skip for now)
		case flowsetID >= 256:
			// Data FlowSet
			template := p.v9Templates[sourceID][flowsetID]
			if template != nil {
				parsedFlows := p.parseV9DataFlowSet(flowsetData, template, sourceAddr, bootTime)
				flows = append(flows, parsedFlows...)
			}
		}

		offset += int(flowsetLen)
	}

	return flows, nil
}

func (p *Parser) parseV9Templates(data []byte, sourceID uint32) {
	offset := 0

	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset:])
		fieldCount := binary.BigEndian.Uint16(data[offset+2:])
		offset += 4

		if int(fieldCount)*4+offset > len(data) {
			break
		}

		template := &Template{
			ID:        templateID,
			FieldDefs: make([]FieldDef, fieldCount),
		}

		for i := 0; i < int(fieldCount); i++ {
			fieldType := binary.BigEndian.Uint16(data[offset:])
			fieldLen := binary.BigEndian.Uint16(data[offset+2:])
			template.FieldDefs[i] = FieldDef{Type: fieldType, Length: fieldLen}
			template.Length += int(fieldLen)
			offset += 4
		}

		p.v9Templates[sourceID][templateID] = template
	}
}

func (p *Parser) parseV9DataFlowSet(data []byte, template *Template, sourceAddr *net.UDPAddr, bootTime time.Time) []types.Flow {
	var flows []types.Flow

	recordLen := template.Length
	if recordLen == 0 {
		return flows
	}

	for offset := 0; offset+recordLen <= len(data); offset += recordLen {
		record := data[offset : offset+recordLen]
		flow := p.parseV9Record(record, template, sourceAddr, bootTime)
		if flow != nil {
			flows = append(flows, *flow)
		}
	}

	return flows
}

func (p *Parser) parseV9Record(record []byte, template *Template, sourceAddr *net.UDPAddr, bootTime time.Time) *types.Flow {
	flow := &types.Flow{
		Version:    types.NetFlowV9,
		ExporterIP: sourceAddr.IP,
		ReceivedAt: time.Now(),
	}

	offset := 0
	for _, field := range template.FieldDefs {
		if offset+int(field.Length) > len(record) {
			return nil
		}

		fieldData := record[offset : offset+int(field.Length)]

		switch field.Type {
		case NF9_IPV4_SRC_ADDR:
			flow.SrcAddr = net.IP(fieldData)
		case NF9_IPV4_DST_ADDR:
			flow.DstAddr = net.IP(fieldData)
		case NF9_IPV6_SRC_ADDR:
			flow.SrcAddr = net.IP(fieldData)
		case NF9_IPV6_DST_ADDR:
			flow.DstAddr = net.IP(fieldData)
		case NF9_L4_SRC_PORT:
			flow.SrcPort = binary.BigEndian.Uint16(fieldData)
		case NF9_L4_DST_PORT:
			flow.DstPort = binary.BigEndian.Uint16(fieldData)
		case NF9_PROTOCOL:
			flow.Protocol = fieldData[0]
		case NF9_IN_BYTES:
			flow.Bytes = readUint(fieldData)
		case NF9_IN_PKTS:
			flow.Packets = readUint(fieldData)
		case NF9_TCP_FLAGS:
			flow.TCPFlags = fieldData[0]
		case NF9_SRC_AS:
			flow.SrcAS = uint32(readUint(fieldData))
		case NF9_DST_AS:
			flow.DstAS = uint32(readUint(fieldData))
		case NF9_INPUT_SNMP:
			flow.InputIf = uint16(readUint(fieldData))
		case NF9_OUTPUT_SNMP:
			flow.OutputIf = uint16(readUint(fieldData))
		case NF9_FIRST_SWITCHED:
			uptime := binary.BigEndian.Uint32(fieldData)
			flow.StartTime = bootTime.Add(time.Duration(uptime) * time.Millisecond)
		case NF9_LAST_SWITCHED:
			uptime := binary.BigEndian.Uint32(fieldData)
			flow.EndTime = bootTime.Add(time.Duration(uptime) * time.Millisecond)
		}

		offset += int(field.Length)
	}

	return flow
}

// readUint reads a variable-length unsigned integer
func readUint(data []byte) uint64 {
	switch len(data) {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(data))
	case 4:
		return uint64(binary.BigEndian.Uint32(data))
	case 8:
		return binary.BigEndian.Uint64(data)
	default:
		return 0
	}
}
