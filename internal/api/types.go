package api

import (
	"netflow-collector/pkg/types"
	"time"
)

// SankeyNode repräsentiert einen Knoten im Sankey-Diagramm
type SankeyNode struct {
	ID      string `json:"id"`
	Type    string `json:"type"`              // "source", "target", "service", "left", "right", "left-if", "right-if"
	Label   string `json:"label"`             // Anzeige-Label (Hostname oder IP)
	SortKey int    `json:"sortKey,omitempty"` // Sortier-Schlüssel für Gruppierung (z.B. Interface-ID)
}

// SankeyLink repräsentiert eine Verbindung zwischen Knoten
type SankeyLink struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Value    uint64 `json:"value"`    // Bytes
	Packets  uint64 `json:"packets"`
	Protocol string `json:"protocol"` // Dominantes Protokoll
	Flows    int    `json:"flows"`    // Anzahl aggregierter Flows
	Inferred bool   `json:"inferred,omitempty"` // True wenn Pfad inferiert wurde (keine echten Daten)
}

// SankeyData ist die Antwort für /api/v1/sankey
type SankeyData struct {
	Mode      string       `json:"mode"` // "ip-to-ip" oder "ip-to-service"
	Nodes     []SankeyNode `json:"nodes"`
	Links     []SankeyLink `json:"links"`
	Generated time.Time    `json:"generated"`
	Filter    string       `json:"filter,omitempty"`
}

// FlowResponse ist ein einzelner Flow für /api/v1/flows
type FlowResponse struct {
	SrcAddr    string    `json:"srcAddr"`
	DstAddr    string    `json:"dstAddr"`
	SrcPort    uint16    `json:"srcPort"`
	DstPort    uint16    `json:"dstPort"`
	Protocol   string    `json:"protocol"`
	Bytes      uint64    `json:"bytes"`
	Packets    uint64    `json:"packets"`
	Service    string    `json:"service,omitempty"`
	ReceivedAt time.Time `json:"receivedAt"`
	Version    string    `json:"version"`
}

// FlowsResponse ist die Antwort für /api/v1/flows
type FlowsResponse struct {
	Flows     []FlowResponse `json:"flows"`
	Total     int            `json:"total"`
	Filtered  int            `json:"filtered"`
	Generated time.Time      `json:"generated"`
	Filter    string         `json:"filter,omitempty"`
}

// StatsResponse ist die Antwort für /api/v1/stats
type StatsResponse struct {
	TotalFlows      uint64    `json:"totalFlows"`
	TotalBytes      uint64    `json:"totalBytes"`
	TotalPackets    uint64    `json:"totalPackets"`
	FlowsPerSecond  float64   `json:"flowsPerSecond"`
	BytesPerSecond  float64   `json:"bytesPerSecond"`
	V5Flows         uint64    `json:"v5Flows"`
	V9Flows         uint64    `json:"v9Flows"`
	IPFIXFlows      uint64    `json:"ipfixFlows"`
	UniqueExporters int       `json:"uniqueExporters"`
	CurrentFlows    int       `json:"currentFlows"`
	MaxFlows        int       `json:"maxFlows"`
	Generated       time.Time `json:"generated"`
}

// ErrorResponse wird bei Fehlern zurückgegeben
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// InterfaceInfo enthält Informationen über ein Interface
type InterfaceInfo struct {
	ID           uint16 `json:"id"`
	ExporterIP   string `json:"exporterIp"`            // IP des Exporters dem dieses Interface gehört
	FlowCount    int    `json:"flowCount"`
	Bytes        uint64 `json:"bytes"`
	IsWAN        bool   `json:"isWan"`                  // Automatisch erkanntes WAN-Interface
	PublicIPs    int    `json:"publicIps"`              // Anzahl einzigartiger öffentlicher IPs
	PrivateIPs   int    `json:"privateIps"`             // Anzahl einzigartiger privater IPs
	TopSubnet    string `json:"topSubnet,omitempty"`    // Häufigstes Subnetz (z.B. "10.0.0.0/24")
	TopSubnetIPs int    `json:"topSubnetIps,omitempty"` // Anzahl IPs in diesem Subnetz
}

// ExporterInfo enthält Informationen über einen Exporter (Router/Firewall)
type ExporterInfo struct {
	IP         string          `json:"ip"`
	Name       string          `json:"name,omitempty"` // Optional: DNS-Name oder manueller Name
	Interfaces []InterfaceInfo `json:"interfaces"`
	WanID      uint16          `json:"wanId"` // WAN-Interface dieses Exporters
}

// InterfacesResponse ist die Antwort für /api/v1/interfaces
type InterfacesResponse struct {
	Exporters  []ExporterInfo  `json:"exporters"`            // Gruppiert nach Exporter
	Interfaces []InterfaceInfo `json:"interfaces,omitempty"` // Flache Liste (Legacy)
	WanID      uint16          `json:"wanId"`                // Globales WAN-Interface (Legacy)
	Generated  time.Time       `json:"generated"`
}

// FlowToResponse konvertiert einen types.Flow zu FlowResponse
func FlowToResponse(f *types.Flow, serviceName string) FlowResponse {
	return FlowResponse{
		SrcAddr:    f.SrcAddr.String(),
		DstAddr:    f.DstAddr.String(),
		SrcPort:    f.SrcPort,
		DstPort:    f.DstPort,
		Protocol:   f.ProtocolName(),
		Bytes:      f.Bytes,
		Packets:    f.Packets,
		Service:    serviceName,
		ReceivedAt: f.ReceivedAt,
		Version:    f.Version.String(),
	}
}
