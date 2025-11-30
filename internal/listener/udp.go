package listener

import (
	"fmt"
	"net"
)

const (
	DefaultPort       = 2055
	MaxPacketSize     = 65535
	DefaultBufferSize = 1024 * 1024 // 1MB
)

// Packet represents a received UDP packet with metadata
type Packet struct {
	Data       []byte
	SourceAddr *net.UDPAddr
}

// UDPListener listens for NetFlow/IPFIX packets
type UDPListener struct {
	conn     *net.UDPConn
	port     int
	packets  chan Packet
	stopChan chan struct{}
}

// New creates a new UDP listener
func New(port int) *UDPListener {
	if port == 0 {
		port = DefaultPort
	}
	return &UDPListener{
		port:     port,
		packets:  make(chan Packet, 1000),
		stopChan: make(chan struct{}),
	}
}

// Start begins listening for UDP packets
func (l *UDPListener) Start() error {
	addr := &net.UDPAddr{
		Port: l.port,
		IP:   net.IPv4zero,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %w", l.port, err)
	}

	// Set receive buffer size
	if err := conn.SetReadBuffer(DefaultBufferSize); err != nil {
		// Non-fatal, just log
		fmt.Printf("Warning: could not set UDP buffer size: %v\n", err)
	}

	l.conn = conn

	go l.readLoop()

	return nil
}

// readLoop continuously reads UDP packets
func (l *UDPListener) readLoop() {
	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-l.stopChan:
			return
		default:
			n, addr, err := l.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-l.stopChan:
					return
				default:
					continue
				}
			}

			// Copy data to avoid buffer reuse issues
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case l.packets <- Packet{Data: data, SourceAddr: addr}:
			default:
				// Channel full, drop packet
			}
		}
	}
}

// Packets returns the channel of received packets
func (l *UDPListener) Packets() <-chan Packet {
	return l.packets
}

// Stop stops the listener
func (l *UDPListener) Stop() {
	close(l.stopChan)
	if l.conn != nil {
		l.conn.Close()
	}
}

// Port returns the listening port
func (l *UDPListener) Port() int {
	return l.port
}
