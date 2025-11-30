package parser

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"netflow-collector/pkg/types"
)

const (
	netflowV5HeaderSize = 24
	netflowV5RecordSize = 48
)

// NetFlow v5 Header structure:
// Bytes 0-1:   Version (5)
// Bytes 2-3:   Count (number of flows)
// Bytes 4-7:   SysUptime (ms since boot)
// Bytes 8-11:  Unix Secs
// Bytes 12-15: Unix Nsecs
// Bytes 16-19: Flow Sequence
// Byte 20:     Engine Type
// Byte 21:     Engine ID
// Bytes 22-23: Sampling Interval

// NetFlow v5 Record structure:
// Bytes 0-3:   Source IP
// Bytes 4-7:   Dest IP
// Bytes 8-11:  Next Hop
// Bytes 12-13: Input Interface
// Bytes 14-15: Output Interface
// Bytes 16-19: Packets
// Bytes 20-23: Bytes (Octets)
// Bytes 24-27: First (SysUptime at start)
// Bytes 28-31: Last (SysUptime at end)
// Bytes 32-33: Source Port
// Bytes 34-35: Dest Port
// Byte 36:     Pad1
// Byte 37:     TCP Flags
// Byte 38:     Protocol
// Byte 39:     ToS
// Bytes 40-41: Source AS
// Bytes 42-43: Dest AS
// Byte 44:     Source Mask
// Byte 45:     Dest Mask
// Bytes 46-47: Pad2

func (p *Parser) parseNetFlowV5(data []byte, sourceAddr *net.UDPAddr) ([]types.Flow, error) {
	if len(data) < netflowV5HeaderSize {
		return nil, fmt.Errorf("NetFlow v5 packet too short for header: %d bytes", len(data))
	}

	// Parse header
	count := binary.BigEndian.Uint16(data[2:4])
	sysUptime := binary.BigEndian.Uint32(data[4:8])
	unixSecs := binary.BigEndian.Uint32(data[8:12])
	unixNsecs := binary.BigEndian.Uint32(data[12:16])

	// Calculate base time
	baseTime := time.Unix(int64(unixSecs), int64(unixNsecs))
	bootTime := baseTime.Add(-time.Duration(sysUptime) * time.Millisecond)

	expectedLen := netflowV5HeaderSize + int(count)*netflowV5RecordSize
	if len(data) < expectedLen {
		return nil, fmt.Errorf("NetFlow v5 packet too short: expected %d bytes, got %d", expectedLen, len(data))
	}

	flows := make([]types.Flow, 0, count)

	for i := 0; i < int(count); i++ {
		offset := netflowV5HeaderSize + i*netflowV5RecordSize
		record := data[offset : offset+netflowV5RecordSize]

		// Parse timestamps relative to boot time
		firstUptime := binary.BigEndian.Uint32(record[24:28])
		lastUptime := binary.BigEndian.Uint32(record[28:32])

		flow := types.Flow{
			Version:    types.NetFlowV5,
			SrcAddr:    net.IP(record[0:4]),
			DstAddr:    net.IP(record[4:8]),
			SrcPort:    binary.BigEndian.Uint16(record[32:34]),
			DstPort:    binary.BigEndian.Uint16(record[34:36]),
			Protocol:   record[38],
			Packets:    uint64(binary.BigEndian.Uint32(record[16:20])),
			Bytes:      uint64(binary.BigEndian.Uint32(record[20:24])),
			StartTime:  bootTime.Add(time.Duration(firstUptime) * time.Millisecond),
			EndTime:    bootTime.Add(time.Duration(lastUptime) * time.Millisecond),
			TCPFlags:   record[37],
			SrcAS:      uint32(binary.BigEndian.Uint16(record[40:42])),
			DstAS:      uint32(binary.BigEndian.Uint16(record[42:44])),
			InputIf:    binary.BigEndian.Uint16(record[12:14]),
			OutputIf:   binary.BigEndian.Uint16(record[14:16]),
			ExporterIP: sourceAddr.IP,
			ReceivedAt: time.Now(),
		}

		flows = append(flows, flow)
	}

	return flows, nil
}
