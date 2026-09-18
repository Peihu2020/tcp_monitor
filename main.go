//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" handshake tcp_handshake.c

// ============ 日志文件管理 ============

const (
	logFilePath  = "/var/log/tcp_monitor.log"
	jsonFilePath = "/var/log/tcp_monitor_json.log"
	maxLogSize   = 10 * 1024 * 1024 // 10MB
)

const (
	DIR_UNKNOWN  = 0
	DIR_INBOUND  = 1
	DIR_OUTBOUND = 2
)

var (
	globalLogWriter  *rotatingWriter
	globalJSONWriter *rotatingWriter
)

type rotatingWriter struct {
	path    string
	maxSize int64
	mu      sync.Mutex
}

func newRotatingWriter(path string, maxSize int64) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	f.Close()
	return &rotatingWriter{path: path, maxSize: maxSize}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	info, err := os.Stat(w.path)
	if err == nil && info.Size() >= w.maxSize {
		if err := os.Truncate(w.path, 0); err != nil {
			return 0, err
		}
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return f.Write(p)
}

// ============ TC EVENT STRUCTURE ============

type TCEvent struct {
	TimestampNS            uint64
	SrcIP                  uint32
	DestIP                 uint32
	SrcPort                uint16
	DestPort               uint16
	EventType              uint8
	Result                 uint8
	IsRetransmit           uint8
	Direction              uint8
	HandshakeDurationMs    uint32
	SynToSynackMs          uint32
	DataToFirstByteMs      uint32
	DataTransferDurationMs uint32
	SeqNum                 uint32
	AckNum                 uint32
	PayloadLen             uint32
	RetransmitCount        uint32
	SynSeq                 uint32
	SynackSeq              uint32
	SynackAck              uint32
	AckSeq                 uint32
	AckAck                 uint32
	TotalBytesSent         uint32
	TotalBytesRcvd         uint32
	TlsClientHelloMs       uint32
	TlsServerHelloMs       uint32
	TlsCertificateMs       uint32
	TlsFinishedMs          uint32
	TlsTotalMs             uint32
	TlsVersion             uint8
	Pad2                   [3]byte
	Domain                 [48]byte
	SocketCookie           uint64
}

// ============ TP EVENT STRUCTURE ============

type TPEvent struct {
	TimestampNS  uint64
	Skaddr       uint64
	SrcIP        uint32
	DestIP       uint32
	SrcPort      uint16
	DestPort     uint16
	OldState     uint32
	NewState     uint32
	Result       uint32
	CreatedNS    uint64
	SocketCookie uint64
}

// ============ TC CONN VALUE (for timeout sweeper) ============

type TCConnKey struct {
	IP1   uint32
	IP2   uint32
	Port1 uint16
	Port2 uint16
}

type TCConnValue struct {
	TCScratchState        uint8
	RetransmitCount       uint8
	IsClient              uint8
	SynackRetransmit      uint8
	_                     [4]byte
	SynTimeNS             uint64
	SynackTimeNS          uint64
	AckTimeNS             uint64
	SynSeq                uint32
	SynackSeq             uint32
	SynackAck             uint32
	AckSeq                uint32
	AckAck                uint32
	_                     [4]byte
	FirstDataFromServerNS uint64
	FirstDataFromClientNS uint64
	TotalBytesSent        uint32
	TotalBytesRcvd        uint32
	HandshakeComplete     uint8
	Pad2                  [3]byte
	Domain                [48]byte
	DomainDetected        uint8
	Pad3                  [3]byte
	TLSStartTimeNS        uint64
	TLSClientHelloNS      uint64
	TLSServerHelloNS      uint64
	TLSCertificateNS      uint64
	TLSFinishedNS         uint64
	TLSState              uint8
	TLSVersion            uint8
	Pad4                  [6]byte
	SocketCookie          uint64
}

// ============ CONSTANTS ============

const (
	TC_EVENT_SYN_SENT          = 1
	TC_EVENT_SYN_ACK_RCVD      = 2
	TC_EVENT_HANDSHAKE_SUCCESS = 3
	TC_EVENT_DATA_SENT         = 4
	TC_EVENT_DATA_RCVD         = 5
	TC_EVENT_DATA_TRANSFER     = 6
	TC_EVENT_SYN_RETRANSMIT    = 7
	TC_EVENT_SYNACK_RETRANSMIT = 8
	TC_EVENT_HANDSHAKE_FAILED  = 9
	TC_EVENT_HANDSHAKE_TIMEOUT = 10
	TC_EVENT_SYN_RCVD          = 11
	TC_EVENT_SYN_ACK_SENT      = 12
)

const (
	TLS_EVENT_CLIENT_HELLO   = 20
	TLS_EVENT_SERVER_HELLO   = 21
	TLS_EVENT_CERTIFICATE    = 22
	TLS_EVENT_FINISHED       = 23
	TLS_EVENT_HANDSHAKE_DONE = 24
)

const (
	TCP_ESTABLISHED  = 1
	TCP_SYN_SENT     = 2
	TCP_SYN_RECV     = 3
	TCP_FIN_WAIT1    = 4
	TCP_FIN_WAIT2    = 5
	TCP_TIME_WAIT    = 6
	TCP_CLOSE        = 7
	TCP_CLOSE_WAIT   = 8
	TCP_LAST_ACK     = 9
	TCP_LISTEN       = 10
	TCP_CLOSING      = 11
	TCP_NEW_SYN_RECV = 12
)

const (
	RESULT_IN_PROGRESS = 0
	RESULT_SUCCESS     = 1
	RESULT_FAILED      = 2
	RESULT_TIMEOUT     = 3
)

const (
	FAIL_NONE                 = 0
	FAIL_RST                  = 1
	FAIL_MAX_RETRANSMIT       = 2
	FAIL_BAD_ACK              = 3
	FAIL_FIN_DURING_HANDSHAKE = 4
	FAIL_TIMEOUT              = 5
	FAIL_HANDSHAKE_ABORTED    = 7
)

const (
	SocketUnknown = 0
	SocketAlive   = 1
	SocketClosed  = 2
)

const aggregatorIdleTimeout = 30 * time.Second
const tcHardTimeout = 1 * time.Hour
const tpHardTimeout = 30 * time.Minute
const recentlyFlushedTTL = 5 * time.Second

const handshakeTimeoutNS = uint64(30 * 1e9)
const sweepInterval = 1 * time.Second

const maxPlausibleBytesPerEvent = uint32(100 * 1024 * 1024)

const recentlyEmittedTTL = 5 * time.Second

var tcpStateNames = map[uint32]string{
	TCP_ESTABLISHED:  "ESTABLISHED",
	TCP_SYN_SENT:     "SYN_SENT",
	TCP_SYN_RECV:     "SYN_RECV",
	TCP_FIN_WAIT1:    "FIN_WAIT1",
	TCP_FIN_WAIT2:    "FIN_WAIT2",
	TCP_TIME_WAIT:    "TIME_WAIT",
	TCP_CLOSE:        "CLOSE",
	TCP_CLOSE_WAIT:   "CLOSE_WAIT",
	TCP_LAST_ACK:     "LAST_ACK",
	TCP_LISTEN:       "LISTEN",
	TCP_CLOSING:      "CLOSING",
	TCP_NEW_SYN_RECV: "NEW_SYN_RECV",
}

var failureReasonNames = map[uint8]string{
	FAIL_NONE:                 "",
	FAIL_RST:                  "rst",
	FAIL_MAX_RETRANSMIT:       "max_retransmit",
	FAIL_BAD_ACK:              "bad_ack",
	FAIL_FIN_DURING_HANDSHAKE: "fin_during_handshake",
	FAIL_TIMEOUT:              "timeout",
	FAIL_HANDSHAKE_ABORTED:    "handshake_aborted",
}

func failureReasonName(r uint8) string {
	if name, ok := failureReasonNames[r]; ok {
		return name
	}
	return fmt.Sprintf("reason_%d", r)
}

func isFailureEvent(t uint8) bool {
	return t == TC_EVENT_HANDSHAKE_FAILED || t == TC_EVENT_HANDSHAKE_TIMEOUT
}

// ============ IP HELPERS ============

func convertSocketIp(ipNum uint32) net.IP {
	ipNetworkOrder := htonl(ipNum)
	return net.IPv4(
		byte(ipNetworkOrder>>24),
		byte(ipNetworkOrder>>16),
		byte(ipNetworkOrder>>8),
		byte(ipNetworkOrder),
	)
}

func htonl(n uint32) uint32 {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], n)
	return binary.LittleEndian.Uint32(tmp[:])
}

func isLoopbackIP(ip uint32) bool {
	b0 := byte(ip)
	b3 := byte(ip >> 24)
	return b0 == 127 || b3 == 127
}

// ============ TIMESTAMP ============

var bootTime time.Time
var bootTimeOnce sync.Once

func getBootTime() (time.Time, error) {
	var err error
	bootTimeOnce.Do(func() {
		data, readErr := os.ReadFile("/proc/stat")
		if readErr != nil {
			err = readErr
			return
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "btime ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					sec, parseErr := strconv.ParseInt(parts[1], 10, 64)
					if parseErr != nil {
						err = parseErr
						return
					}
					bootTime = time.Unix(sec, 0)
					return
				}
			}
		}
		err = fmt.Errorf("boot time not found in /proc/stat")
	})
	return bootTime, err
}

func convertEBPFTimestamp(timestampNS uint64) time.Time {
	bt, err := getBootTime()
	if err != nil {
		return time.Now()
	}
	return bt.Add(time.Duration(timestampNS))
}

// ============ HELPERS ============

func getTCPStateName(state uint32) string {
	if state == 0 {
		return "OBSERVATION_START"
	}
	if name, ok := tcpStateNames[state]; ok {
		return name
	}
	return fmt.Sprintf("STATE_%d", state)
}

func getDomain(domainBytes [48]byte) string {
	for i, b := range domainBytes {
		if b == 0 {
			return string(domainBytes[:i])
		}
	}
	return string(domainBytes[:])
}

func getTLSVersion(version uint8) string {
	switch version {
	case 0x01:
		return "TLS 1.0"
	case 0x02:
		return "TLS 1.1"
	case 0x03:
		return "TLS 1.2"
	case 0x04:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%02x", version)
	}
}

// ============ TC AGGREGATOR ============

type TCStateChange struct {
	Time    time.Time
	Step    string
	Elapsed uint32
}

type TCAggregatedConnection struct {
	// Client / server orientation, locked the first time we observe a SYN.
	// SrcIP/SrcPort below always store the client; DestIP/DestPort the server.
	clientIP         string
	clientPort       uint16
	serverIP         string
	serverPort       uint16
	orientationKnown bool

	SrcIP    string
	DestIP   string
	SrcPort  uint16
	DestPort uint16
	Domain   string

	StartTime         time.Time
	LastUpdate        time.Time
	FirstPacket       time.Time
	LastPacket        time.Time
	SnapshotEmittedAt time.Time

	SynSeq uint32

	TCPHandshakeMs uint32
	TCPRttMs       uint32
	Retransmits    uint32

	SYNRetransmits    uint32
	SYNACKRetransmits uint32
	RetransmitEvents  uint32

	TLSHandshakeMs uint32
	TLSVersion     uint8
	TTFBMs         uint32

	TotalBytesSent uint32
	TotalBytesRcvd uint32
	DataTransfers  int

	Timeline []TCStateChange

	Result     uint8
	IsComplete bool

	FailureReason uint8
	IsFailed      bool

	// Direction observed from the wire (0=unknown, 1=inbound, 2=outbound).
	DirectionSeen  uint8
	DirectionKnown bool

	SocketCookie uint64
}

type TCAggregator struct {
	mu          sync.Mutex
	Connections map[string]*TCAggregatedConnection
	OutputChan  chan *TCAggregatedConnection
	Timeout     time.Duration
	stopChan    chan struct{}
	wg          sync.WaitGroup

	FilterLoopback bool

	tpAggregator *TPAggregator

	recentlyFlushedMu sync.Mutex
	recentlyFlushed   map[string]time.Time
}

func NewTCAggregator(filterLoopback bool) *TCAggregator {
	return &TCAggregator{
		Connections:     make(map[string]*TCAggregatedConnection),
		OutputChan:      make(chan *TCAggregatedConnection, 8192),
		Timeout:         aggregatorIdleTimeout,
		stopChan:        make(chan struct{}),
		FilterLoopback:  filterLoopback,
		recentlyFlushed: make(map[string]time.Time),
	}
}

func getTCConnKey(event *TCEvent) string {
	var ip1, ip2 uint32
	var port1, port2 uint16
	if event.SrcIP < event.DestIP ||
		(event.SrcIP == event.DestIP && event.SrcPort < event.DestPort) {
		ip1, ip2 = event.SrcIP, event.DestIP
		port1, port2 = event.SrcPort, event.DestPort
	} else {
		ip1, ip2 = event.DestIP, event.SrcIP
		port1, port2 = event.DestPort, event.SrcPort
	}
	return fmt.Sprintf("%d:%d:%d:%d", ip1, port1, ip2, port2)
}

func (ta *TCAggregator) Start() {
	ta.wg.Add(1)
	go func() {
		defer ta.wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ta.sweep()
			case <-ta.stopChan:
				return
			}
		}
	}()
}

func (ta *TCAggregator) Stop() {
	close(ta.stopChan)
	ta.wg.Wait()
	close(ta.OutputChan)
}

func (ta *TCAggregator) sweep() {
	ta.mu.Lock()
	var toFlush []*TCAggregatedConnection
	now := time.Now()
	for key, conn := range ta.Connections {
		idle := now.Sub(conn.LastUpdate)

		if idle > tcHardTimeout {
			if !conn.IsFailed {
				conn.Result = RESULT_SUCCESS
			}
			toFlush = append(toFlush, conn)
			delete(ta.Connections, key)
			continue
		}

		if idle <= ta.Timeout {
			continue
		}

		if ta.tpAggregator != nil {
			state := ta.tpAggregator.GetSocketState(
				conn.SrcIP, conn.SrcPort, conn.DestIP, conn.DestPort)

			switch state {
			case SocketAlive:
				continue
			case SocketUnknown:
				if idle < ta.Timeout*2 {
					continue
				}
			case SocketClosed:
			}
		}

		if !conn.IsFailed {
			conn.Result = RESULT_SUCCESS
		}
		toFlush = append(toFlush, conn)
		delete(ta.Connections, key)
	}
	ta.mu.Unlock()
	for _, conn := range toFlush {
		ta.emit(conn)
	}
}

func (ta *TCAggregator) emit(conn *TCAggregatedConnection) {
	if conn.SrcIP != "" && conn.DestIP != "" {
		tk := fmt.Sprintf("%s:%d-%s:%d",
			conn.SrcIP, conn.SrcPort, conn.DestIP, conn.DestPort)
		ta.recentlyFlushedMu.Lock()
		ta.recentlyFlushed[tk] = time.Now()
		ta.recentlyFlushedMu.Unlock()
	}

	select {
	case ta.OutputChan <- conn:
	default:
	}
}

func (ta *TCAggregator) isRecentlyFlushed(srcIP string, srcPort uint16,
	dstIP string, dstPort uint16) bool {
	tk := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	ta.recentlyFlushedMu.Lock()
	defer ta.recentlyFlushedMu.Unlock()
	t, ok := ta.recentlyFlushed[tk]
	if !ok {
		return false
	}
	if time.Since(t) > recentlyFlushedTTL {
		delete(ta.recentlyFlushed, tk)
		return false
	}
	return true
}

func (ta *TCAggregator) GetOutputChan() <-chan *TCAggregatedConnection {
	return ta.OutputChan
}

// isNewConnectionOnReusedTuple reports whether an incoming SYN belongs to a
// different connection than the one currently tracked under the same 5-tuple.
func isNewConnectionOnReusedTuple(conn *TCAggregatedConnection, event *TCEvent) bool {
	if conn.SynSeq == 0 {
		if conn.SocketCookie != 0 && event.SocketCookie != 0 &&
			conn.SocketCookie != event.SocketCookie {
			return true
		}
		return false
	}
	if event.SynSeq == conn.SynSeq {
		return false
	}
	return true
}

func (ta *TCAggregator) AddEvent(event *TCEvent) {
	if ta.FilterLoopback {
		if isLoopbackIP(event.SrcIP) || isLoopbackIP(event.DestIP) {
			return
		}
	}

	ta.mu.Lock()
	defer ta.mu.Unlock()

	key := getTCConnKey(event)
	conn, exists := ta.Connections[key]
	eventTime := convertEBPFTimestamp(event.TimestampNS)
	domain := getDomain(event.Domain)

	if exists && (event.EventType == TC_EVENT_SYN_SENT ||
		event.EventType == TC_EVENT_SYN_RCVD) {
		if isNewConnectionOnReusedTuple(conn, event) {
			ta.emit(conn)
			delete(ta.Connections, key)
			conn = nil
			exists = false
		}
	}

	if !exists {
		isNewConnEvent := (event.EventType == TC_EVENT_SYN_SENT ||
			event.EventType == TC_EVENT_SYN_RCVD)
		if !isNewConnEvent {
			if ta.isRecentlyFlushed(
				convertSocketIp(event.SrcIP).String(), event.SrcPort,
				convertSocketIp(event.DestIP).String(), event.DestPort) {
				return
			}
			if ta.isRecentlyFlushed(
				convertSocketIp(event.DestIP).String(), event.DestPort,
				convertSocketIp(event.SrcIP).String(), event.SrcPort) {
				return
			}
		}

		conn = &TCAggregatedConnection{
			StartTime:   eventTime,
			FirstPacket: eventTime,
			LastUpdate:  eventTime,
			LastPacket:  eventTime,
		}
		ta.Connections[key] = conn
	}

	if !conn.orientationKnown &&
		(event.EventType == TC_EVENT_SYN_SENT ||
			event.EventType == TC_EVENT_SYN_RCVD) {
		conn.clientIP = convertSocketIp(event.SrcIP).String()
		conn.clientPort = event.SrcPort
		conn.serverIP = convertSocketIp(event.DestIP).String()
		conn.serverPort = event.DestPort
		conn.orientationKnown = true
	}

	if (event.EventType == TC_EVENT_SYN_SENT ||
		event.EventType == TC_EVENT_SYN_RCVD) &&
		event.Direction != 0 &&
		!conn.DirectionKnown {
		conn.DirectionSeen = event.Direction
		conn.DirectionKnown = true
	}

	if (event.EventType == TC_EVENT_SYN_SENT ||
		event.EventType == TC_EVENT_SYN_RCVD) &&
		event.SynSeq != 0 && conn.SynSeq == 0 {
		conn.SynSeq = event.SynSeq
	}

	if conn.SrcIP == "" && conn.orientationKnown {
		conn.SrcIP = conn.clientIP
		conn.DestIP = conn.serverIP
		conn.SrcPort = conn.clientPort
		conn.DestPort = conn.serverPort
	}

	if eventTime.Before(conn.FirstPacket) {
		conn.FirstPacket = eventTime
	}
	conn.LastUpdate = eventTime
	conn.LastPacket = eventTime
	if conn.Domain == "" && domain != "" {
		conn.Domain = domain
	}

	if conn.SocketCookie == 0 && event.SocketCookie != 0 {
		conn.SocketCookie = event.SocketCookie
	}

	if isFailureEvent(event.EventType) {
		conn.IsFailed = true
		conn.Result = RESULT_FAILED
		if conn.FailureReason == FAIL_NONE {
			conn.FailureReason = event.Result
		}
		ta.emit(conn)
		delete(ta.Connections, key)
		return
	}

	if event.EventType == TC_EVENT_HANDSHAKE_SUCCESS {
		if event.HandshakeDurationMs > conn.TCPHandshakeMs {
			conn.TCPHandshakeMs = event.HandshakeDurationMs
		}
		if conn.SnapshotEmittedAt.IsZero() {
			snapshot := *conn
			snapshot.IsComplete = false
			snapshot.Result = RESULT_IN_PROGRESS
			conn.SnapshotEmittedAt = time.Now()
			ta.emit(&snapshot)
		}
	}
	if event.EventType == TC_EVENT_SYN_ACK_RCVD {
		if event.SynToSynackMs > conn.TCPRttMs {
			conn.TCPRttMs = event.SynToSynackMs
		}
	}
	if event.RetransmitCount > conn.Retransmits {
		conn.Retransmits = event.RetransmitCount
	}

	if event.IsRetransmit != 0 {
		conn.RetransmitEvents++
	}
	switch event.EventType {
	case TC_EVENT_SYN_RETRANSMIT:
		if event.RetransmitCount > conn.SYNRetransmits {
			conn.SYNRetransmits = event.RetransmitCount
		}
	case TC_EVENT_SYNACK_RETRANSMIT:
		conn.SYNACKRetransmits++
	}

	if event.TlsVersion > 0 {
		conn.TLSVersion = event.TlsVersion
	}
	if event.TlsTotalMs > conn.TLSHandshakeMs {
		conn.TLSHandshakeMs = event.TlsTotalMs
	}

	elapsed := uint32(0)
	if !conn.StartTime.IsZero() && eventTime.After(conn.StartTime) {
		elapsed = uint32(eventTime.Sub(conn.StartTime).Milliseconds())
	}

	switch event.EventType {
	case TC_EVENT_SYN_SENT:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-SYN", elapsed})
	case TC_EVENT_SYN_RETRANSMIT:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-SYN-REXMIT", elapsed})
	case TC_EVENT_SYN_ACK_RCVD:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-SYN-ACK", elapsed})
	case TC_EVENT_SYNACK_RETRANSMIT:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-SYN-ACK-REXMIT", elapsed})
	case TC_EVENT_HANDSHAKE_SUCCESS:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-ACK", elapsed})
	case TLS_EVENT_CLIENT_HELLO:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TLS-ClientHello", elapsed})
	case TLS_EVENT_SERVER_HELLO:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TLS-ServerHello", elapsed})
	case TLS_EVENT_CERTIFICATE:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TLS-Certificate", elapsed})
	case TLS_EVENT_FINISHED:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TLS-Finished", elapsed})
	case TLS_EVENT_HANDSHAKE_DONE:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TLS-HandshakeDone", elapsed})
	case TC_EVENT_SYN_RCVD:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-SYN-RCVD", elapsed})
	case TC_EVENT_SYN_ACK_SENT:
		conn.Timeline = append(conn.Timeline, TCStateChange{eventTime, "TCP-SYN-ACK-SENT", elapsed})
	}

	if conn.SnapshotEmittedAt.IsZero() &&
		(event.EventType == TC_EVENT_DATA_SENT ||
			event.EventType == TC_EVENT_DATA_RCVD ||
			event.EventType == TC_EVENT_DATA_TRANSFER) {
		snapshot := *conn
		snapshot.IsComplete = false
		snapshot.Result = RESULT_IN_PROGRESS
		conn.SnapshotEmittedAt = time.Now()
		ta.emit(&snapshot)
	}

	if event.EventType == TC_EVENT_DATA_RCVD && event.DataToFirstByteMs > 0 && conn.TTFBMs == 0 {
		conn.TTFBMs = event.DataToFirstByteMs
	}

	if event.TotalBytesSent > 0 && event.TotalBytesSent < maxPlausibleBytesPerEvent {
		if event.TotalBytesSent > conn.TotalBytesSent {
			conn.TotalBytesSent = event.TotalBytesSent
		}
	}
	if event.TotalBytesRcvd > 0 && event.TotalBytesRcvd < maxPlausibleBytesPerEvent {
		if event.TotalBytesRcvd > conn.TotalBytesRcvd {
			conn.TotalBytesRcvd = event.TotalBytesRcvd
		}
	}

	if event.EventType == TC_EVENT_DATA_TRANSFER {
		conn.DataTransfers++
	}
}

// ============ HANDSHAKE TIMEOUT SWEEPER ============

type HandshakeTimeoutSweeper struct {
	Map      *ebpf.Map
	TCProc   *TCAggregator
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewHandshakeTimeoutSweeper(m *ebpf.Map, agg *TCAggregator) *HandshakeTimeoutSweeper {
	return &HandshakeTimeoutSweeper{
		Map:      m,
		TCProc:   agg,
		stopChan: make(chan struct{}),
	}
}

func (s *HandshakeTimeoutSweeper) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.sweepOnce()
			case <-s.stopChan:
				return
			}
		}
	}()
}

func (s *HandshakeTimeoutSweeper) Stop() {
	close(s.stopChan)
	s.wg.Wait()
}

func (s *HandshakeTimeoutSweeper) sweepOnce() {
	if s.Map == nil {
		return
	}
	bt, err := getBootTime()
	if err != nil {
		return
	}
	nowKtime := uint64(time.Since(bt))

	var key TCConnKey
	var val TCConnValue
	iter := s.Map.Iterate()
	var stale []TCConnKey

	for iter.Next(&key, &val) {
		if val.TCScratchState != TCP_SYN_SENT && val.TCScratchState != TCP_SYN_RECV {
			continue
		}
		if val.SynTimeNS == 0 {
			continue
		}
		if nowKtime < val.SynTimeNS {
			continue
		}
		if nowKtime-val.SynTimeNS < handshakeTimeoutNS {
			continue
		}

		ev := &TCEvent{
			TimestampNS:     nowKtime,
			SrcIP:           key.IP1,
			DestIP:          key.IP2,
			SrcPort:         key.Port1,
			DestPort:        key.Port2,
			EventType:       TC_EVENT_HANDSHAKE_TIMEOUT,
			Result:          FAIL_TIMEOUT,
			SynSeq:          val.SynSeq,
			SynackSeq:       val.SynackSeq,
			SynackAck:       val.SynackAck,
			RetransmitCount: uint32(val.RetransmitCount),
			SocketCookie:    val.SocketCookie,
		}
		if val.SynTimeNS != 0 {
			ev.HandshakeDurationMs = uint32((nowKtime - val.SynTimeNS) / 1_000_000)
		}
		if val.SynTimeNS != 0 && val.SynackTimeNS != 0 {
			ev.SynToSynackMs = uint32((val.SynackTimeNS - val.SynTimeNS) / 1_000_000)
		}
		copy(ev.Domain[:], val.Domain[:])

		s.TCProc.AddEvent(ev)
		stale = append(stale, key)
	}
	if err := iter.Err(); err != nil {
		log.Printf("⚠️ tc_conn_map iterate: %v", err)
		return
	}

	for _, k := range stale {
		_ = s.Map.Delete(&k)
	}
}

// ============ TP AGGREGATOR ============

type TPStateChange struct {
	Time     time.Time
	OldState uint32
	NewState uint32
}

type TPAggregatedConnection struct {
	Skaddr   uint64
	SrcIP    string
	DestIP   string
	SrcPort  uint16
	DestPort uint16

	CreatedTime     time.Time
	LastStateChange time.Time

	StateHistory []TPStateChange

	CurrentState uint32
	PrevState    uint32

	WasEverEstablished bool
	DroppedAfterEstab  bool
	ObservedOnlyAtEnd  bool
	IsComplete         bool
	FlushedByIdle      bool

	clientIsSrc bool
	clientKnown bool
	finSeen     bool

	Result uint8

	FailureReason uint8

	SocketCookie uint64

	SnapshotEmittedAt time.Time
}

type TPAggregator struct {
	mu          sync.Mutex
	Connections map[uint64]*TPAggregatedConnection
	OutputChan  chan *TPAggregatedConnection
	Timeout     time.Duration
	stopChan    chan struct{}
	wg          sync.WaitGroup

	FilterLoopback bool

	byTuple map[string]uint64

	recentlyMu      sync.Mutex
	recentlyEmitted map[uint64]time.Time

	eventCount uint64 // 收到的事件总数
	connCount  uint64 // 创建的新连接数
	emitCount  uint64 // emit 的连接数
	dropCount  uint64 // emit 丢弃的连接数
}

func NewTPAggregator(filterLoopback bool) *TPAggregator {
	return &TPAggregator{
		Connections:     make(map[uint64]*TPAggregatedConnection),
		OutputChan:      make(chan *TPAggregatedConnection, 512),
		Timeout:         aggregatorIdleTimeout,
		stopChan:        make(chan struct{}),
		FilterLoopback:  filterLoopback,
		byTuple:         make(map[string]uint64),
		recentlyEmitted: make(map[uint64]time.Time),
	}
}

func tupleKey(srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
}

func (ta *TPAggregator) GetSocketState(srcIP string, srcPort uint16,
	dstIP string, dstPort uint16) int {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	skaddr, ok := ta.byTuple[tupleKey(srcIP, srcPort, dstIP, dstPort)]
	if !ok {
		return SocketUnknown
	}
	tpConn, ok := ta.Connections[skaddr]
	if !ok {
		return SocketUnknown
	}
	switch tpConn.CurrentState {
	case TCP_CLOSE, TCP_TIME_WAIT, TCP_CLOSING:
		return SocketClosed
	default:
		return SocketAlive
	}
}

func (ta *TPAggregator) isRecentlyEmitted(skaddr uint64) bool {
	ta.recentlyMu.Lock()
	defer ta.recentlyMu.Unlock()
	t, ok := ta.recentlyEmitted[skaddr]
	if !ok {
		return false
	}
	if time.Since(t) > recentlyEmittedTTL {
		delete(ta.recentlyEmitted, skaddr)
		return false
	}
	return true
}

func (ta *TPAggregator) markEmitted(skaddr uint64) {
	ta.recentlyMu.Lock()
	defer ta.recentlyMu.Unlock()
	ta.recentlyEmitted[skaddr] = time.Now()
}

func (ta *TPAggregator) cleanupRecentlyEmitted() {
	ta.recentlyMu.Lock()
	defer ta.recentlyMu.Unlock()
	cutoff := time.Now().Add(-recentlyEmittedTTL)
	for skaddr, t := range ta.recentlyEmitted {
		if t.Before(cutoff) {
			delete(ta.recentlyEmitted, skaddr)
		}
	}
}

func (ta *TPAggregator) Start() {
	ta.wg.Add(1)
	go func() {
		defer ta.wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ta.sweep()
			case <-ta.stopChan:
				return
			}
		}
	}()
}

func (ta *TPAggregator) Stop() {
	close(ta.stopChan)
	ta.wg.Wait()
	close(ta.OutputChan)
}

func (ta *TPAggregator) sweep() {
	ta.mu.Lock()
	var toFlush []*TPAggregatedConnection
	now := time.Now()
	for key, conn := range ta.Connections {
		idle := now.Sub(conn.LastStateChange)

		isTerminal := conn.CurrentState == TCP_CLOSE ||
			conn.CurrentState == TCP_TIME_WAIT ||
			conn.CurrentState == TCP_CLOSING ||
			conn.IsComplete ||
			conn.Result == RESULT_FAILED

		if isTerminal {
			if idle > ta.Timeout {
				toFlush = append(toFlush, conn)
				delete(ta.Connections, key)
			}
			continue
		}

		if conn.WasEverEstablished && !conn.DroppedAfterEstab {
			if idle > tpHardTimeout {
				conn.Result = RESULT_TIMEOUT
				toFlush = append(toFlush, conn)
				delete(ta.Connections, key)
			}
			continue
		}

		if idle > ta.Timeout {
			toFlush = append(toFlush, conn)
			delete(ta.Connections, key)
		}
	}
	ta.mu.Unlock()

	ta.cleanupRecentlyEmitted()

	for _, conn := range toFlush {
		ta.mu.Lock()
		delete(ta.byTuple, tupleKey(conn.SrcIP, conn.SrcPort, conn.DestIP, conn.DestPort))
		ta.mu.Unlock()
		ta.emit(conn)
	}
}

func (ta *TPAggregator) emit(conn *TPAggregatedConnection) {
	select {
	case ta.OutputChan <- conn:
		atomic.AddUint64(&ta.emitCount, 1)
	default:
		atomic.AddUint64(&ta.dropCount, 1)
	}
}

func (ta *TPAggregator) GetOutputChan() <-chan *TPAggregatedConnection {
	return ta.OutputChan
}

func (ta *TPAggregator) AddEvent(event *TPEvent) {
	atomic.AddUint64(&ta.eventCount, 1)
	if ta.FilterLoopback {
		if isLoopbackIP(event.SrcIP) || isLoopbackIP(event.DestIP) {
			return
		}
	}

	// if ta.isRecentlyEmitted(event.Skaddr) {
	// 	return
	// }

	ta.mu.Lock()
	defer ta.mu.Unlock()

	conn, exists := ta.Connections[event.Skaddr]
	eventTime := convertEBPFTimestamp(event.TimestampNS)

	if !exists {
		atomic.AddUint64(&ta.connCount, 1)
		createdTime := convertEBPFTimestamp(event.CreatedNS)
		conn = &TPAggregatedConnection{
			Skaddr:          event.Skaddr,
			CreatedTime:     createdTime,
			LastStateChange: eventTime,
		}
		ta.Connections[event.Skaddr] = conn
	}

	if conn.SrcIP == "" || conn.SrcIP == "0.0.0.0" {
		conn.SrcIP = convertSocketIp(event.SrcIP).String()
	}
	if conn.DestIP == "" || conn.DestIP == "0.0.0.0" {
		conn.DestIP = convertSocketIp(event.DestIP).String()
	}
	if conn.SrcPort == 0 && event.SrcPort != 0 {
		conn.SrcPort = event.SrcPort
	}
	if conn.DestPort == 0 && event.DestPort != 0 {
		conn.DestPort = event.DestPort
	}

	if conn.SrcIP != "" && conn.SrcIP != "0.0.0.0" &&
		conn.DestIP != "" && conn.DestIP != "0.0.0.0" &&
		conn.SrcPort != 0 && conn.DestPort != 0 {
		ta.byTuple[tupleKey(conn.SrcIP, conn.SrcPort, conn.DestIP, conn.DestPort)] = event.Skaddr
	}

	if conn.SocketCookie == 0 && event.SocketCookie != 0 {
		conn.SocketCookie = event.SocketCookie
	}

	oldState := conn.CurrentState
	newState := event.NewState

	conn.StateHistory = append(conn.StateHistory, TPStateChange{
		Time:     eventTime,
		OldState: oldState,
		NewState: newState,
	})

	// if oldState == newState && len(conn.StateHistory) > 1 {
	// 	conn.LastStateChange = eventTime
	// 	return
	// }

	conn.PrevState = oldState
	conn.CurrentState = newState
	conn.LastStateChange = eventTime

	if oldState == 0 && (newState == TCP_CLOSE || newState == TCP_TIME_WAIT || newState == TCP_CLOSING) {
		conn.ObservedOnlyAtEnd = true
	}

	switch newState {
	case TCP_ESTABLISHED, TCP_FIN_WAIT1, TCP_FIN_WAIT2,
		TCP_CLOSE_WAIT, TCP_CLOSING, TCP_LAST_ACK, TCP_TIME_WAIT:
		conn.WasEverEstablished = true
	}
	if newState == TCP_ESTABLISHED && conn.SnapshotEmittedAt.IsZero() {
		snapshot := *conn
		conn.SnapshotEmittedAt = time.Now()
		ta.emit(&snapshot)
	}

	if oldState == TCP_ESTABLISHED &&
		(newState == TCP_FIN_WAIT1 || newState == TCP_CLOSE_WAIT) {
		conn.finSeen = true
	}

	if conn.WasEverEstablished &&
		newState == TCP_CLOSE &&
		oldState == TCP_ESTABLISHED &&
		event.Result == FAIL_RST {
		conn.DroppedAfterEstab = true
	}

	switch newState {
	case TCP_CLOSE, TCP_TIME_WAIT, TCP_CLOSING:
		conn.IsComplete = true
		switch {
		case conn.DroppedAfterEstab:
			conn.Result = RESULT_FAILED
		case newState == TCP_CLOSE && !conn.WasEverEstablished:
			conn.Result = RESULT_FAILED
		default:
			conn.Result = RESULT_SUCCESS
		}
		if event.Result != 0 {
			conn.FailureReason = uint8(event.Result)
			conn.Result = RESULT_FAILED
		}
		delete(ta.Connections, event.Skaddr)
		delete(ta.byTuple, tupleKey(conn.SrcIP, conn.SrcPort, conn.DestIP, conn.DestPort))
		ta.markEmitted(event.Skaddr)
		go ta.emit(conn)
	}
}

// ============ JSON OUTPUT (TC + TP, separate kinds) ============

type JSONTC struct {
	Kind         string `json:"kind"`
	SocketCookie int64  `json:"socket_cookie,omitempty"`

	ClientIP   string `json:"client_ip"`
	ClientPort uint16 `json:"client_port"`
	ServerIP   string `json:"server_ip"`
	ServerPort uint16 `json:"server_port"`
	Domain     string `json:"domain,omitempty"`

	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time,omitempty"`
	DurationMs int64  `json:"duration_ms"`

	Result        string `json:"result"`
	FailureReason string `json:"failure_reason,omitempty"`

	TCPHandshakeMs uint32 `json:"tcp_handshake_ms,omitempty"`
	TCPRttMs       uint32 `json:"tcp_rtt_ms,omitempty"`
	TLSHandshakeMs uint32 `json:"tls_handshake_ms,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	TTFBMs         uint32 `json:"ttfb_ms,omitempty"`

	BytesSent     uint32 `json:"bytes_sent,omitempty"`
	BytesReceived uint32 `json:"bytes_received,omitempty"`
	DataTransfers int    `json:"data_transfers,omitempty"`

	SYNRetransmits    uint32 `json:"syn_retransmits,omitempty"`
	SYNACKRetransmits uint32 `json:"synack_retransmits,omitempty"`
	RetransmitEvents  uint32 `json:"retransmit_events,omitempty"`

	Direction string `json:"direction,omitempty"`
	IsFinal   bool   `json:"is_final"`
}

type JSONTP struct {
	Kind         string `json:"kind"`
	SocketCookie int64  `json:"socket_cookie,omitempty"`
	Skaddr       string `json:"skaddr,omitempty"`

	ClientIP   string `json:"client_ip"`
	ClientPort uint16 `json:"client_port"`
	ServerIP   string `json:"server_ip"`
	ServerPort uint16 `json:"server_port"`

	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time,omitempty"`
	DurationMs int64  `json:"duration_ms"`

	StateResult   string `json:"state_result"`
	FailureReason string `json:"failure_reason,omitempty"`

	SynSentAt     string `json:"syn_sent_at,omitempty"`
	SynRecvAt     string `json:"syn_recv_at,omitempty"`
	EstablishedAt string `json:"established_at,omitempty"`
	CloseAt       string `json:"close_at,omitempty"`

	TCPState   string `json:"tcp_state,omitempty"`
	TCPStateAt string `json:"tcp_state_at,omitempty"`

	Direction string `json:"direction,omitempty"`
	IsFinal   bool   `json:"is_final"`
}

func emitJSON(v any) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("⚠️ json marshal: %v", err)
		return
	}
	if globalJSONWriter != nil {
		fmt.Fprintln(globalJSONWriter, string(out))
	} else {
		fmt.Fprintln(os.Stdout, string(out))
	}
}

func outputTCJSON(tc *TCAggregatedConnection, isFinal bool) {
	if tc == nil {
		return
	}
	j := JSONTC{
		Kind:              "tc",
		ClientIP:          tc.SrcIP,
		ClientPort:        tc.SrcPort,
		ServerIP:          tc.DestIP,
		ServerPort:        tc.DestPort,
		Domain:            tc.Domain,
		TCPHandshakeMs:    tc.TCPHandshakeMs,
		TCPRttMs:          tc.TCPRttMs,
		TLSHandshakeMs:    tc.TLSHandshakeMs,
		TTFBMs:            tc.TTFBMs,
		BytesSent:         tc.TotalBytesSent,
		BytesReceived:     tc.TotalBytesRcvd,
		DataTransfers:     tc.DataTransfers,
		SYNRetransmits:    tc.SYNRetransmits,
		SYNACKRetransmits: tc.SYNACKRetransmits,
		RetransmitEvents:  tc.RetransmitEvents,
		IsFinal:           isFinal,
	}
	if tc.SocketCookie != 0 {
		j.SocketCookie = int64(tc.SocketCookie)
	}
	if tc.TLSVersion > 0 {
		j.TLSVersion = getTLSVersion(tc.TLSVersion)
	}
	if !tc.StartTime.IsZero() {
		j.StartTime = tc.StartTime.Format(time.RFC3339Nano)
	}
	if !tc.LastPacket.IsZero() {
		j.EndTime = tc.LastPacket.Format(time.RFC3339Nano)
	}
	if !tc.StartTime.IsZero() && tc.LastPacket.After(tc.StartTime) {
		j.DurationMs = tc.LastPacket.Sub(tc.StartTime).Milliseconds()
	}
	switch {
	case tc.IsFailed || tc.Result == RESULT_FAILED:
		j.Result = "failed"
		j.FailureReason = failureReasonName(tc.FailureReason)
	case tc.Result == RESULT_SUCCESS:
		j.Result = "success"
	default:
		j.Result = "in_progress"
	}
	if tc.DirectionKnown {
		switch tc.DirectionSeen {
		case DIR_OUTBOUND:
			j.Direction = "outbound"
		case DIR_INBOUND:
			j.Direction = "inbound"
		}
	}
	emitJSON(j)
}

func outputTPJSON(tp *TPAggregatedConnection, isFinal bool) {
	if tp == nil {
		return
	}
	j := JSONTP{
		Kind:       "tp",
		Skaddr:     fmt.Sprintf("0x%x", tp.Skaddr),
		ClientIP:   tp.SrcIP,
		ClientPort: tp.SrcPort,
		ServerIP:   tp.DestIP,
		ServerPort: tp.DestPort,
		IsFinal:    isFinal,
	}
	if tp.SocketCookie != 0 {
		j.SocketCookie = int64(tp.SocketCookie)
	}
	if !tp.CreatedTime.IsZero() {
		j.StartTime = tp.CreatedTime.Format(time.RFC3339Nano)
	}
	if !tp.LastStateChange.IsZero() {
		j.EndTime = tp.LastStateChange.Format(time.RFC3339Nano)
	}
	if !tp.CreatedTime.IsZero() && tp.LastStateChange.After(tp.CreatedTime) {
		j.DurationMs = tp.LastStateChange.Sub(tp.CreatedTime).Milliseconds()
	}
	switch tp.Result {
	case RESULT_SUCCESS:
		j.StateResult = "success"
	case RESULT_FAILED:
		if tp.ObservedOnlyAtEnd {
			j.StateResult = "unknown_observed_at_end"
		} else {
			j.StateResult = "failed"
		}
	case RESULT_TIMEOUT:
		j.StateResult = "timeout_forced_flush"
	default:
		j.StateResult = "in_progress"
	}
	if tp.FailureReason != 0 {
		j.FailureReason = failureReasonName(tp.FailureReason)
	}
	if t := firstTimeForState(tp, TCP_SYN_SENT); t != nil {
		j.SynSentAt = t.Format(time.RFC3339Nano)
	}
	if t := firstTimeForState(tp, TCP_SYN_RECV); t != nil {
		j.SynRecvAt = t.Format(time.RFC3339Nano)
	}
	if t := firstTimeForState(tp, TCP_ESTABLISHED); t != nil {
		j.EstablishedAt = t.Format(time.RFC3339Nano)
	}
	if t := firstTimeForState(tp, TCP_CLOSE); t != nil {
		j.CloseAt = t.Format(time.RFC3339Nano)
	}
	if tp.CurrentState != 0 {
		j.TCPState = getTCPStateName(tp.CurrentState)
		if !tp.LastStateChange.IsZero() {
			j.TCPStateAt = tp.LastStateChange.Format(time.RFC3339Nano)
		}
	}
	if len(tp.StateHistory) > 0 {
		switch tp.StateHistory[0].NewState {
		case TCP_SYN_SENT:
			j.Direction = "outbound"
		case TCP_SYN_RECV:
			j.Direction = "inbound"
		}
	}
	emitJSON(j)
}

// ============ PROGRAM SETUP ============

type AttachedProgram struct {
	Objs           *handshakeObjects
	IngressLink    link.Link
	EgressLink     link.Link
	TracepointLink link.Link
	TCReader       *perf.Reader
	TPReader       *perf.Reader
	IfaceName      string
}

var globalTracepointLink link.Link

func setupHandshakeProgramOnInterface(iface string) (*AttachedProgram, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	objs := &handshakeObjects{}
	if err := loadHandshakeObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading handshake objects: %w", err)
	}

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("getting interface %s: %w", iface, err)
	}

	var ingressLink, egressLink link.Link

	ingressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
		Interface: ifaceObj.Index,
	})

	if err == nil {
		log.Printf("✅ Attached ingress TCX to %s", iface)
		egressLink, err = link.AttachTCX(link.TCXOptions{
			Program:   objs.EgressProgFunc,
			Attach:    ebpf.AttachTCXEgress,
			Interface: ifaceObj.Index,
		})
		if err != nil {
			ingressLink.Close()
			objs.Close()
			return nil, fmt.Errorf("attaching egress TCX to %s: %w", iface, err)
		}
		log.Printf("✅ Attached egress TCX to %s", iface)
	} else {
		log.Printf("TCX not supported, falling back to legacy TC for %s", iface)

		tcPaths := []string{"/sbin/tc", "/usr/sbin/tc", "/bin/tc", "/usr/bin/tc"}
		tcCmd := ""
		for _, path := range tcPaths {
			if _, err := os.Stat(path); err == nil {
				tcCmd = path
				break
			}
		}
		if tcCmd == "" {
			objs.Close()
			return nil, fmt.Errorf("tc command not found")
		}

		if err := exec.Command(tcCmd, "qdisc", "add", "dev", iface, "clsact").Run(); err != nil {
			if err := exec.Command(tcCmd, "qdisc", "replace", "dev", iface, "clsact").Run(); err != nil {
				objs.Close()
				return nil, fmt.Errorf("failed to create clsact qdisc: %w", err)
			}
		}

		ingressFd := objs.IngressProgFunc.FD()
		egressFd := objs.EgressProgFunc.FD()

		ingressCmd := exec.Command(tcCmd, "filter", "add", "dev", iface, "ingress",
			"bpf", "da", "fd", strconv.Itoa(ingressFd))
		if err := ingressCmd.Run(); err != nil {
			ingressCmd = exec.Command(tcCmd, "filter", "replace", "dev", iface, "ingress",
				"bpf", "da", "fd", strconv.Itoa(ingressFd))
			if err := ingressCmd.Run(); err != nil {
				_ = exec.Command(tcCmd, "qdisc", "del", "dev", iface, "clsact").Run()
				objs.Close()
				return nil, fmt.Errorf("failed to attach ingress: %w", err)
			}
		}

		egressCmd := exec.Command(tcCmd, "filter", "add", "dev", iface, "egress",
			"bpf", "da", "fd", strconv.Itoa(egressFd))
		if err := egressCmd.Run(); err != nil {
			egressCmd = exec.Command(tcCmd, "filter", "replace", "dev", iface, "egress",
				"bpf", "da", "fd", strconv.Itoa(egressFd))
			if err := egressCmd.Run(); err != nil {
				_ = exec.Command(tcCmd, "filter", "del", "dev", iface, "ingress").Run()
				_ = exec.Command(tcCmd, "qdisc", "del", "dev", iface, "clsact").Run()
				objs.Close()
				return nil, fmt.Errorf("failed to attach egress: %w", err)
			}
		}
		log.Printf("✅ Attached legacy TC to %s", iface)
	}

	var tracepointLink link.Link
	if globalTracepointLink == nil {
		tp, err := link.Tracepoint("sock", "inet_sock_set_state",
			objs.TraceTcpState, nil)
		if err != nil {
			log.Printf("⚠️ Failed to attach tracepoint: %v", err)
		} else {
			tracepointLink = tp
			globalTracepointLink = tp
			log.Printf("✅ Attached tracepoint sock:inet_sock_set_state")
		}
	}

	tcReader, err := perf.NewReader(objs.TcEvents, os.Getpagesize()*256)
	if err != nil {
		if ingressLink != nil {
			ingressLink.Close()
		}
		if egressLink != nil {
			egressLink.Close()
		}
		if tracepointLink != nil {
			tracepointLink.Close()
			globalTracepointLink = nil
		}
		objs.Close()
		return nil, fmt.Errorf("creating TC perf reader: %w", err)
	}

	tpReader, err := perf.NewReader(objs.TpEvents, os.Getpagesize()*2048)
	if err != nil {
		tcReader.Close()
		if ingressLink != nil {
			ingressLink.Close()
		}
		if egressLink != nil {
			egressLink.Close()
		}
		if tracepointLink != nil {
			tracepointLink.Close()
			globalTracepointLink = nil
		}
		objs.Close()
		return nil, fmt.Errorf("creating TP perf reader: %w", err)
	}

	return &AttachedProgram{
		Objs:           objs,
		IngressLink:    ingressLink,
		EgressLink:     egressLink,
		TracepointLink: tracepointLink,
		TCReader:       tcReader,
		TPReader:       tpReader,
		IfaceName:      iface,
	}, nil
}

func (ap *AttachedProgram) Close() {
	if ap.TCReader != nil {
		ap.TCReader.Close()
	}
	if ap.TPReader != nil {
		ap.TPReader.Close()
	}
	if ap.IngressLink != nil {
		ap.IngressLink.Close()
	}
	if ap.EgressLink != nil {
		ap.EgressLink.Close()
	}
	if ap.TracepointLink != nil {
		ap.TracepointLink.Close()
		globalTracepointLink = nil
	}
	if ap.Objs != nil {
		ap.Objs.Close()
	}
}

// ============ EVENT PROCESSING ============

func processTCEvents(reader *perf.Reader, agg *TCAggregator) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("⚠️ TC read error: %v", err)
			continue
		}
		if record.LostSamples > 0 {
			log.Printf("⚠️ Lost %d TC events (perf ring full!)", record.LostSamples)
			continue
		}
		event, err := readTCEvent(record.RawSample)
		if err != nil {
			log.Printf("⚠️ TC parse error (%d bytes): %v", len(record.RawSample), err)
			continue
		}
		agg.AddEvent(event)
	}
}

func processTPEvents(reader *perf.Reader, agg *TPAggregator) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("⚠️ TP read error: %v", err)
			continue
		}
		if record.LostSamples > 0 {
			log.Printf("⚠️ Lost %d TP events (perf ring full!)", record.LostSamples)
			continue
		}
		event, err := readTPEvent(record.RawSample)
		if err != nil {
			log.Printf("⚠️ TP parse error (%d bytes): %v", len(record.RawSample), err)
			continue
		}
		agg.AddEvent(event)
	}
}

func readTCEvent(data []byte) (*TCEvent, error) {
	expected := int(unsafe.Sizeof(TCEvent{}))
	if len(data) < expected {
		return nil, fmt.Errorf("short data: got %d, want %d", len(data), expected)
	}
	var event TCEvent
	if err := binary.Read(bytes.NewReader(data[:expected]), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

func readTPEvent(data []byte) (*TPEvent, error) {
	expected := int(unsafe.Sizeof(TPEvent{}))
	if len(data) < expected {
		return nil, fmt.Errorf("short data: got %d, want %d", len(data), expected)
	}
	var event TPEvent
	if err := binary.Read(bytes.NewReader(data[:expected]), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

// ============ INTERFACE DETECTION ============

func isPhysicalInterface(iface *net.Interface) bool {
	name := iface.Name
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if len(iface.HardwareAddr) == 0 {
		return false
	}
	for _, pattern := range []string{"eth", "en", "ens", "enp", "eno"} {
		if strings.HasPrefix(name, pattern) {
			return true
		}
	}
	return false
}

// ============ MAIN ============

func main() {
	log.SetFlags(0)

	logWriter, err := newRotatingWriter(logFilePath, maxLogSize)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", logFilePath, err)
	}
	globalLogWriter = logWriter
	log.SetOutput(logWriter)
	log.SetFlags(log.LstdFlags)

	initLocalIPs()
	startLocalIPsRefresh(60 * time.Second)

	jsonWriter, err := newRotatingWriter(jsonFilePath, maxLogSize)
	if err != nil {
		log.Fatalf("Failed to open JSON file %s: %v", jsonFilePath, err)
	}
	globalJSONWriter = jsonWriter

	log.Printf("=== TCP Monitor starting ===")

	var (
		flagIncludeLocal bool
		flagInterfaces   string
	)

	flag.BoolVar(&flagIncludeLocal, "include-local", false,
		"Include loopback connections (127.0.0.0/8). Default: excluded.")
	flag.StringVar(&flagInterfaces, "ifaces", "",
		"Comma-separated interfaces to monitor. Default: auto-detect physical NICs.")

	var (
		flagPGEnable   bool
		flagPGDSN      string
		flagPGHost     string
		flagPGPort     int
		flagPGUser     string
		flagPGPassword string
		flagPGDatabase string
		flagPGSSLMode  string
	)
	flag.BoolVar(&flagPGEnable, "pg-enable", false,
		"Enable PostgreSQL output (upsert into tcp_tc_connections / tcp_state_connections).")
	flag.StringVar(&flagPGDSN, "pg-dsn", "",
		"PostgreSQL DSN, e.g. postgres://user:pass@host:5432/db. Overrides -pg-host/-pg-port/...")
	flag.StringVar(&flagPGHost, "pg-host", "127.0.0.1", "PostgreSQL host")
	flag.IntVar(&flagPGPort, "pg-port", 5432, "PostgreSQL port")
	flag.StringVar(&flagPGUser, "pg-user", "postgres", "PostgreSQL user")
	flag.StringVar(&flagPGPassword, "pg-password", "", "PostgreSQL password")
	flag.StringVar(&flagPGDatabase, "pg-database", "tcp_monitor", "PostgreSQL database")
	flag.StringVar(&flagPGSSLMode, "pg-sslmode", "disable", "PostgreSQL sslmode")

	flag.Parse()

	tcSize := int(unsafe.Sizeof(TCEvent{}))
	tpSize := int(unsafe.Sizeof(TPEvent{}))
	log.Printf("=== STRUCT SIZE CHECK ===")
	log.Printf("TCEvent size = %d bytes (expect 168)", tcSize)
	log.Printf("TPEvent size = %d bytes (expect 56)", tpSize)
	log.Printf("=========================")
	if tcSize != 168 {
		log.Fatalf("FATAL: TCEvent size %d != 168", tcSize)
	}
	if tpSize != 56 {
		log.Fatalf("FATAL: TPEvent size %d != 56", tpSize)
	}

	var interfaces []string
	if flagInterfaces != "" {
		for _, s := range strings.Split(flagInterfaces, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				interfaces = append(interfaces, s)
			}
		}
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("Failed to list interfaces: %v", err)
		}
		for _, iface := range ifaces {
			if isPhysicalInterface(&iface) {
				interfaces = append(interfaces, iface.Name)
			}
		}
	}

	if len(interfaces) == 0 {
		log.Fatal("No physical network interfaces found")
	}

	log.Printf("🔍 TCP Monitor starting on: %v", interfaces)
	if flagIncludeLocal {
		log.Printf("   🌐 Loopback: INCLUDED")
	} else {
		log.Printf("   🚫 Loopback: EXCLUDED")
	}
	log.Printf("   Output: JSON (kind=tc / kind=tp) + optional PostgreSQL")
	log.Printf("   TC idle timeout:    %v", aggregatorIdleTimeout)
	log.Printf("   TC hard cap:        %v", tcHardTimeout)
	log.Printf("   TP hard cap:        %v", tpHardTimeout)
	log.Printf("   Log file:  %s", logFilePath)
	log.Printf("   JSON file: %s", jsonFilePath)
	log.Printf("   Max file size: %d MB (overwritten when exceeded)", maxLogSize/(1024*1024))

	filterLoopback := !flagIncludeLocal

	tcAgg := NewTCAggregator(filterLoopback)
	tpAgg := NewTPAggregator(filterLoopback)

	tcAgg.tpAggregator = tpAgg

	tcAgg.Start()
	tpAgg.Start()
	defer tcAgg.Stop()
	defer tpAgg.Stop()

	// ---------------- PostgreSQL writers ----------------
	var tcPG, tpPG *pgWriter
	if flagPGEnable {
		connStr := flagPGDSN
		if connStr == "" {
			connStr = buildPGConnString(flagPGHost, flagPGPort,
				flagPGUser, flagPGPassword, flagPGDatabase, flagPGSSLMode)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pool, err := newPGPool(ctx, connStr)
		cancel()
		if err != nil {
			log.Fatalf("❌ Failed to init PostgreSQL pool: %v", err)
		}

		tcPG = newPGWriter(pool, "tc", tcUpsertSQL, func(r any) []any {
			return tcRowArgs(r.(*pgRowTC))
		})
		tpPG = newPGWriter(pool, "tp", tpUpsertSQL, func(r any) []any {
			return tpRowArgs(r.(*pgRowTP))
		})
		tcPG.Start()
		tpPG.Start()
		defer func() {
			tcPG.Stop()
			tpPG.Stop()
			pool.Close()
		}()
		log.Printf("✅ PostgreSQL writers enabled: %s", redactConnString(connStr))
	} else {
		log.Printf("ℹ️  PostgreSQL output disabled (use -pg-enable to turn on)")
	}

	// ---------------- eBPF attach ----------------
	var attachedPrograms []*AttachedProgram
	defer func() {
		for _, ap := range attachedPrograms {
			ap.Close()
		}
	}()

	var sweepers []*HandshakeTimeoutSweeper

	for _, iface := range interfaces {
		ap, err := setupHandshakeProgramOnInterface(iface)
		if err != nil {
			log.Printf("⚠️ Failed to attach to %s: %v", iface, err)
			continue
		}
		attachedPrograms = append(attachedPrograms, ap)
		go processTCEvents(ap.TCReader, tcAgg)
		go processTPEvents(ap.TPReader, tpAgg)

		if ap.Objs != nil && ap.Objs.TcConnMap != nil {
			s := NewHandshakeTimeoutSweeper(ap.Objs.TcConnMap, tcAgg)
			s.Start()
			sweepers = append(sweepers, s)
		}
	}

	if len(attachedPrograms) == 0 {
		log.Fatal("Failed to attach to any interface")
	}

	log.Printf("✅ Monitoring %d interface(s)", len(attachedPrograms))

	// ---------------- Periodic stats ----------------
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			tcAgg.mu.Lock()
			tcCount := len(tcAgg.Connections)
			tcAgg.mu.Unlock()

			tpAgg.mu.Lock()
			tpCount := len(tpAgg.Connections)
			tpAgg.mu.Unlock()

			tcAgg.recentlyFlushedMu.Lock()
			rfCount := len(tcAgg.recentlyFlushed)
			tcAgg.recentlyFlushedMu.Unlock()

			if tcPG != nil && tpPG != nil {
				wTC, fTC, dTC, sTC := tcPG.Stats()
				wTP, fTP, dTP, sTP := tpPG.Stats()
				log.Printf("📊 tc_conns=%d tp_conns=%d recently_flushed=%d | tc_pg(w=%d f=%d d=%d s=%d) tp_pg(w=%d f=%d d=%d s=%d)",
					tcCount, tpCount, rfCount,
					wTC, fTC, dTC, sTC,
					wTP, fTP, dTP, sTP)
			} else {
				log.Printf("📊 tc_conns=%d tp_conns=%d recently_flushed=%d",
					tcCount, tpCount, rfCount)
			}
		}
	}()

	// ---------------- Output fan-out ----------------
	go func() {
		for conn := range tcAgg.GetOutputChan() {
			final := conn.IsComplete || conn.IsFailed || conn.Result == RESULT_SUCCESS || conn.Result == RESULT_FAILED
			outputTCJSON(conn, final)
			if tcPG != nil {
				row := buildTCRow(conn, final)
				if row != nil {
					tcPG.Enqueue(row)
				}
			}
		}
	}()

	go func() {
		for conn := range tpAgg.GetOutputChan() {
			final := conn.IsComplete || conn.Result == RESULT_FAILED || conn.Result == RESULT_TIMEOUT
			outputTPJSON(conn, final)
			if tpPG != nil {
				row := buildTPRow(conn, final)
				if row != nil {
					tpPG.Enqueue(row)
				}
			}
		}
	}()

	// ---------------- Wait for signal ----------------
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	for _, s := range sweepers {
		s.Stop()
	}

	log.Printf("👋 Shutting down...")
}
