package parser

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"netflow-collector/pkg/types"
)

const (
	ipfixHeaderSize    = 16
	ipfixSetHeaderSize = 4
)

// IPFIX field type IDs (same as NetFlow v9 for common fields)
const (
	IPFIX_OCTET_DELTA_COUNT      = 1
	IPFIX_PACKET_DELTA_COUNT     = 2
	IPFIX_PROTOCOL_IDENTIFIER    = 4
	IPFIX_IP_CLASS_OF_SERVICE    = 5
	IPFIX_TCP_CONTROL_BITS       = 6
	IPFIX_SOURCE_TRANSPORT_PORT  = 7
	IPFIX_SOURCE_IPV4_ADDRESS    = 8
	IPFIX_SOURCE_IPV4_PREFIX_LEN = 9
	IPFIX_INGRESS_INTERFACE      = 10
	IPFIX_DEST_TRANSPORT_PORT    = 11
	IPFIX_DEST_IPV4_ADDRESS      = 12
	IPFIX_DEST_IPV4_PREFIX_LEN   = 13
	IPFIX_EGRESS_INTERFACE       = 14
	IPFIX_IP_NEXT_HOP_IPV4       = 15
	IPFIX_BGP_SOURCE_AS          = 16
	IPFIX_BGP_DEST_AS            = 17
	IPFIX_FLOW_START_SYS_UP_TIME = 22
	IPFIX_FLOW_END_SYS_UP_TIME   = 21
	IPFIX_SOURCE_IPV6_ADDRESS    = 27
	IPFIX_DEST_IPV6_ADDRESS      = 28
	IPFIX_FLOW_START_MILLISEC    = 152
	IPFIX_FLOW_END_MILLISEC      = 153
	IPFIX_FLOW_START_MICROSEC    = 154
	IPFIX_FLOW_END_MICROSEC      = 155
)

// IPFIX Header:
// Bytes 0-1:   Version (10)
// Bytes 2-3:   Length
// Bytes 4-7:   Export Time (Unix Seconds)
// Bytes 8-11:  Sequence Number
// Bytes 12-15: Observation Domain ID

func (p *Parser) parseIPFIX(data []byte, sourceAddr *net.UDPAddr) ([]types.Flow, error) {
	if len(data) < ipfixHeaderSize {
		return nil, fmt.Errorf("IPFIX packet too short for header: %d bytes", len(data))
	}

	// Parse header
	length := binary.BigEndian.Uint16(data[2:4])
	exportTime := binary.BigEndian.Uint32(data[4:8])
	observationDomainID := binary.BigEndian.Uint32(data[12:16])

	if int(length) > len(data) {
		return nil, fmt.Errorf("IPFIX packet length mismatch: header says %d, got %d", length, len(data))
	}

	baseTime := time.Unix(int64(exportTime), 0)

	// Ensure template map exists for this observation domain
	if p.ipfixTemplates[observationDomainID] == nil {
		p.ipfixTemplates[observationDomainID] = make(map[uint16]*Template)
	}

	var flows []types.Flow
	offset := ipfixHeaderSize

	// Process Sets
	for offset+ipfixSetHeaderSize <= int(length) {
		setID := binary.BigEndian.Uint16(data[offset:])
		setLen := binary.BigEndian.Uint16(data[offset+2:])

		if setLen < 4 || offset+int(setLen) > int(length) {
			break
		}

		setData := data[offset+4 : offset+int(setLen)]

		switch {
		case setID == 2:
			// Template Set
			p.parseIPFIXTemplates(setData, observationDomainID)
		case setID == 3:
			// Options Template Set (skip for now)
		case setID >= 256:
			// Data Set
			template := p.ipfixTemplates[observationDomainID][setID]
			if template != nil {
				parsedFlows := p.parseIPFIXDataSet(setData, template, sourceAddr, baseTime)
				flows = append(flows, parsedFlows...)
			}
		}

		offset += int(setLen)
	}

	return flows, nil
}

func (p *Parser) parseIPFIXTemplates(data []byte, observationDomainID uint32) {
	offset := 0

	for offset+4 <= len(data) {
		templateID := binary.BigEndian.Uint16(data[offset:])
		fieldCount := binary.BigEndian.Uint16(data[offset+2:])
		offset += 4

		template := &Template{
			ID:        templateID,
			FieldDefs: make([]FieldDef, 0, fieldCount),
		}

		for i := 0; i < int(fieldCount) && offset+4 <= len(data); i++ {
			fieldType := binary.BigEndian.Uint16(data[offset:])
			fieldLen := binary.BigEndian.Uint16(data[offset+2:])

			// Handle enterprise bit (bit 15 of field type)
			isEnterprise := (fieldType & 0x8000) != 0
			fieldType = fieldType & 0x7FFF

			offset += 4

			// Skip enterprise number if present
			if isEnterprise && offset+4 <= len(data) {
				offset += 4
			}

			template.FieldDefs = append(template.FieldDefs, FieldDef{Type: fieldType, Length: fieldLen})
			template.Length += int(fieldLen)
		}

		p.ipfixTemplates[observationDomainID][templateID] = template
	}
}

func (p *Parser) parseIPFIXDataSet(data []byte, template *Template, sourceAddr *net.UDPAddr, baseTime time.Time) []types.Flow {
	var flows []types.Flow

	recordLen := template.Length
	if recordLen == 0 {
		return flows
	}

	for offset := 0; offset+recordLen <= len(data); offset += recordLen {
		record := data[offset : offset+recordLen]
		flow := p.parseIPFIXRecord(record, template, sourceAddr, baseTime)
		if flow != nil {
			flows = append(flows, *flow)
		}
	}

	return flows
}

func (p *Parser) parseIPFIXRecord(record []byte, template *Template, sourceAddr *net.UDPAddr, baseTime time.Time) *types.Flow {
	flow := &types.Flow{
		Version:    types.IPFIX,
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
		case IPFIX_SOURCE_IPV4_ADDRESS:
			flow.SrcAddr = net.IP(fieldData)
		case IPFIX_DEST_IPV4_ADDRESS:
			flow.DstAddr = net.IP(fieldData)
		case IPFIX_SOURCE_IPV6_ADDRESS:
			flow.SrcAddr = net.IP(fieldData)
		case IPFIX_DEST_IPV6_ADDRESS:
			flow.DstAddr = net.IP(fieldData)
		case IPFIX_SOURCE_TRANSPORT_PORT:
			flow.SrcPort = binary.BigEndian.Uint16(fieldData)
		case IPFIX_DEST_TRANSPORT_PORT:
			flow.DstPort = binary.BigEndian.Uint16(fieldData)
		case IPFIX_PROTOCOL_IDENTIFIER:
			flow.Protocol = fieldData[0]
		case IPFIX_OCTET_DELTA_COUNT:
			flow.Bytes = readUint(fieldData)
		case IPFIX_PACKET_DELTA_COUNT:
			flow.Packets = readUint(fieldData)
		case IPFIX_TCP_CONTROL_BITS:
			if len(fieldData) >= 1 {
				flow.TCPFlags = fieldData[len(fieldData)-1]
			}
		case IPFIX_BGP_SOURCE_AS:
			flow.SrcAS = uint32(readUint(fieldData))
		case IPFIX_BGP_DEST_AS:
			flow.DstAS = uint32(readUint(fieldData))
		case IPFIX_INGRESS_INTERFACE:
			flow.InputIf = uint16(readUint(fieldData))
		case IPFIX_EGRESS_INTERFACE:
			flow.OutputIf = uint16(readUint(fieldData))
		case IPFIX_FLOW_START_SYS_UP_TIME:
			uptime := binary.BigEndian.Uint32(fieldData)
			flow.StartTime = baseTime.Add(-time.Duration(uptime) * time.Millisecond)
		case IPFIX_FLOW_END_SYS_UP_TIME:
			uptime := binary.BigEndian.Uint32(fieldData)
			flow.EndTime = baseTime.Add(-time.Duration(uptime) * time.Millisecond)
		case IPFIX_FLOW_START_MILLISEC:
			ms := binary.BigEndian.Uint64(fieldData)
			flow.StartTime = time.UnixMilli(int64(ms))
		case IPFIX_FLOW_END_MILLISEC:
			ms := binary.BigEndian.Uint64(fieldData)
			flow.EndTime = time.UnixMilli(int64(ms))
		}

		offset += int(field.Length)
	}

	return flow
}
