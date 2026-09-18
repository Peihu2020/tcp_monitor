package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ============================================================================
// Hostname (resolved once, cached)
// ============================================================================

var (
	globalHostname   string
	hostnameResolved bool
	hostnameMu       sync.Mutex
)

func hostname() string {
	hostnameMu.Lock()
	defer hostnameMu.Unlock()
	if hostnameResolved {
		return globalHostname
	}
	hostnameResolved = true
	if h, err := os.Hostname(); err == nil && h != "" {
		globalHostname = h
		return globalHostname
	}
	if b, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		h := strings.TrimSpace(string(b))
		if h != "" {
			globalHostname = h
			return globalHostname
		}
	}
	globalHostname = "unknown"
	return globalHostname
}

// ============================================================================
// pgRowTC — one row of tcp_tc_connections
// ============================================================================

type pgRowTC struct {
	SocketCookie int64
	TupleKey     string
	Hostname     string

	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int

	Domain *string

	StartTime  *time.Time
	EndTime    *time.Time
	DurationMs *int64

	Result        *string
	FailureReason *string

	TCPHandshakeMs *int
	TCPRttMs       *int
	TLSHandshakeMs *int
	TLSVersion     *string
	TTFBMs         *int

	BytesSent     *int64
	BytesReceived *int64
	DataTransfers *int

	SYNRetransmits   *int
	RetransmitEvents *int

	TCSynAt          *time.Time
	TCSynAckAt       *time.Time
	TCAckAt          *time.Time
	TCSynRexmitAt    *time.Time
	TCSynAckRexmitAt *time.Time

	TLSClientHelloAt   *time.Time
	TLSServerHelloAt   *time.Time
	TLSCertificateAt   *time.Time
	TLSFinishedAt      *time.Time
	TLSHandshakeDoneAt *time.Time

	TCState   *string
	TCStateAt *time.Time

	Direction *string

	IsFinal bool
}

// ============================================================================
// pgRowTP — one row of tcp_state_connections
// ============================================================================

type pgRowTP struct {
	SocketCookie int64
	TupleKey     string
	Hostname     string

	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int

	StartTime  *time.Time
	EndTime    *time.Time
	DurationMs *int64

	StateResult   *string
	FailureReason *string

	SynSentAt     *time.Time
	SynRecvAt     *time.Time
	EstablishedAt *time.Time
	FinWait1At    *time.Time
	FinWait2At    *time.Time
	CloseWaitAt   *time.Time
	ClosingAt     *time.Time
	LastAckAt     *time.Time
	TimeWaitAt    *time.Time
	CloseAt       *time.Time

	TCPState   *string
	TCPStateAt *time.Time

	Direction *string

	IsFinal bool
}

// ============================================================================
// PGWriter — generic batched upsert writer
// ============================================================================

type pgWriter struct {
	pool *pgxpool.Pool

	ch     chan any
	stopCh chan struct{}
	wg     sync.WaitGroup

	sql           string
	buildArgs     func(any) []any
	flushInterval time.Duration
	batchSize     int

	label string

	mu           sync.Mutex
	dropped      uint64
	written      uint64
	failedCount  uint64
	skippedCount uint64
}

func newPGPool(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("parse pg config: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping pg: %w", err)
	}
	return pool, nil
}

func newPGWriter(pool *pgxpool.Pool, label, sql string, buildArgs func(any) []any) *pgWriter {
	return &pgWriter{
		pool:          pool,
		ch:            make(chan any, 65536),
		stopCh:        make(chan struct{}),
		sql:           sql,
		buildArgs:     buildArgs,
		flushInterval: 500 * time.Millisecond,
		batchSize:     512,
		label:         label,
	}
}

func (w *pgWriter) Start() {
	w.wg.Add(1)
	go w.run()
}

func (w *pgWriter) Stop() {
	close(w.stopCh)
	w.wg.Wait()
	w.drain()
}

func (w *pgWriter) Enqueue(row any) {
	select {
	case w.ch <- row:
	default:
		w.mu.Lock()
		w.dropped++
		w.mu.Unlock()
	}
}

func (w *pgWriter) drain() {
	for {
		select {
		case row := <-w.ch:
			if row != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := w.writeOne(ctx, row); err != nil {
					log.Printf("⚠️ pg[%s] drain write: %v", w.label, err)
				}
				cancel()
			}
		default:
			return
		}
	}
}

func (w *pgWriter) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	buf := make([]any, 0, w.batchSize)

	flush := func() {
		if len(buf) == 0 {
			return
		}
		n := len(buf)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := w.writeBatch(ctx, buf)
		cancel()
		if err != nil {
			w.mu.Lock()
			w.failedCount += uint64(n)
			w.mu.Unlock()
			log.Printf("⚠️ pg[%s] batch write failed (%d rows): %v", w.label, n, err)
		} else {
			w.mu.Lock()
			w.written += uint64(n)
			w.mu.Unlock()
		}
		buf = buf[:0]
	}

	for {
		select {
		case row := <-w.ch:
			if row == nil {
				flush()
				return
			}
			buf = append(buf, row)
			if len(buf) >= w.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stopCh:
			flush()
			return
		}
	}
}

func (w *pgWriter) writeOne(ctx context.Context, row any) error {
	_, err := w.pool.Exec(ctx, w.sql, w.buildArgs(row)...)
	return err
}

func (w *pgWriter) writeBatch(ctx context.Context, rows []any) error {
	if len(rows) == 1 {
		return w.writeOne(ctx, rows[0])
	}
	batch := &pgx.Batch{}
	for _, row := range rows {
		batch.Queue(w.sql, w.buildArgs(row)...)
	}
	br := w.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := range rows {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return nil
}

// Stats returns the high-level counters used by the periodic log.
func (w *pgWriter) Stats() (written, failed, dropped, skipped uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written, w.failedCount, w.dropped, w.skippedCount
}

// ============================================================================
// TC upsert
// ============================================================================

const tcUpsertSQL = `
INSERT INTO tcp_tc_connections (
	socket_cookie, tuple_key, hostname,
	client_ip, client_port, server_ip, server_port, domain,
	start_time, end_time, duration_ms, result, failure_reason,
	tcp_handshake_ms, tcp_rtt_ms, tls_handshake_ms, tls_version, ttfb_ms,
	bytes_sent, bytes_received, data_transfers,
	syn_retransmits, retransmit_events,
	tc_syn_at, tc_syn_ack_at, tc_ack_at, tc_syn_rexmit_at, tc_synack_rexmit_at,
	tls_client_hello_at, tls_server_hello_at, tls_certificate_at,
	tls_finished_at, tls_handshake_done_at,
	tc_state, tc_state_at, direction,
	is_final, updated_at
) VALUES (
	$1, $2, $3,
	$4, $5, $6, $7, $8,
	$9, $10, $11, $12, $13,
	$14, $15, $16, $17, $18,
	$19, $20, $21,
	$22, $23,
	$24, $25, $26, $27, $28,
	$29, $30, $31, $32, $33,
	$34, $35, $36,
	$37, now()
)
ON CONFLICT (socket_cookie) DO UPDATE SET
	tuple_key          = EXCLUDED.tuple_key,
	hostname           = COALESCE(EXCLUDED.hostname, tcp_tc_connections.hostname),
	client_ip          = EXCLUDED.client_ip,
	client_port        = EXCLUDED.client_port,
	server_ip          = EXCLUDED.server_ip,
	server_port        = EXCLUDED.server_port,
	domain             = COALESCE(EXCLUDED.domain, tcp_tc_connections.domain),
	start_time         = LEAST(COALESCE(tcp_tc_connections.start_time, EXCLUDED.start_time), EXCLUDED.start_time),
	end_time           = GREATEST(COALESCE(tcp_tc_connections.end_time, EXCLUDED.end_time), EXCLUDED.end_time),
	duration_ms        = EXCLUDED.duration_ms,
	result             = CASE
	                       WHEN EXCLUDED.result IS NULL OR EXCLUDED.result = 'in_progress'
	                       THEN tcp_tc_connections.result
	                       ELSE EXCLUDED.result
	                     END,
	failure_reason     = COALESCE(EXCLUDED.failure_reason, tcp_tc_connections.failure_reason),
	tcp_handshake_ms   = EXCLUDED.tcp_handshake_ms,
	tcp_rtt_ms         = EXCLUDED.tcp_rtt_ms,
	tls_handshake_ms   = EXCLUDED.tls_handshake_ms,
	tls_version        = EXCLUDED.tls_version,
	ttfb_ms            = EXCLUDED.ttfb_ms,
	bytes_sent         = EXCLUDED.bytes_sent,
	bytes_received     = EXCLUDED.bytes_received,
	data_transfers     = EXCLUDED.data_transfers,
	syn_retransmits    = EXCLUDED.syn_retransmits,
	retransmit_events  = EXCLUDED.retransmit_events,
	tc_syn_at              = COALESCE(tcp_tc_connections.tc_syn_at,             EXCLUDED.tc_syn_at),
	tc_syn_ack_at          = COALESCE(tcp_tc_connections.tc_syn_ack_at,         EXCLUDED.tc_syn_ack_at),
	tc_ack_at              = COALESCE(tcp_tc_connections.tc_ack_at,             EXCLUDED.tc_ack_at),
	tc_syn_rexmit_at       = COALESCE(tcp_tc_connections.tc_syn_rexmit_at,      EXCLUDED.tc_syn_rexmit_at),
	tc_synack_rexmit_at    = COALESCE(tcp_tc_connections.tc_synack_rexmit_at,   EXCLUDED.tc_synack_rexmit_at),
	tls_client_hello_at    = COALESCE(tcp_tc_connections.tls_client_hello_at,   EXCLUDED.tls_client_hello_at),
	tls_server_hello_at    = COALESCE(tcp_tc_connections.tls_server_hello_at,   EXCLUDED.tls_server_hello_at),
	tls_certificate_at     = COALESCE(tcp_tc_connections.tls_certificate_at,    EXCLUDED.tls_certificate_at),
	tls_finished_at        = COALESCE(tcp_tc_connections.tls_finished_at,       EXCLUDED.tls_finished_at),
	tls_handshake_done_at  = COALESCE(tcp_tc_connections.tls_handshake_done_at, EXCLUDED.tls_handshake_done_at),
	tc_state               = EXCLUDED.tc_state,
	tc_state_at            = EXCLUDED.tc_state_at,
	direction              = COALESCE(EXCLUDED.direction, tcp_tc_connections.direction),
	is_final               = EXCLUDED.is_final,
	updated_at             = now()
`

func tcRowArgs(r *pgRowTC) []any {
	return []any{
		r.SocketCookie, r.TupleKey, r.Hostname,
		r.ClientIP, r.ClientPort, r.ServerIP, r.ServerPort, r.Domain,
		r.StartTime, r.EndTime, r.DurationMs, r.Result, r.FailureReason,
		r.TCPHandshakeMs, r.TCPRttMs, r.TLSHandshakeMs, r.TLSVersion, r.TTFBMs,
		r.BytesSent, r.BytesReceived, r.DataTransfers,
		r.SYNRetransmits, r.RetransmitEvents,
		r.TCSynAt, r.TCSynAckAt, r.TCAckAt, r.TCSynRexmitAt, r.TCSynAckRexmitAt,
		r.TLSClientHelloAt, r.TLSServerHelloAt, r.TLSCertificateAt,
		r.TLSFinishedAt, r.TLSHandshakeDoneAt,
		r.TCState, r.TCStateAt, r.Direction,
		r.IsFinal,
	}
}

// ============================================================================
// TP upsert
// ============================================================================

const tpUpsertSQL = `
INSERT INTO tcp_state_connections (
	socket_cookie, tuple_key, hostname,
	client_ip, client_port, server_ip, server_port,
	start_time, end_time, duration_ms, state_result, failure_reason,
	syn_sent_at, syn_recv_at, established_at,
	fin_wait1_at, fin_wait2_at, close_wait_at,
	closing_at, last_ack_at, time_wait_at, close_at,
	tcp_state, tcp_state_at, direction,
	is_final, updated_at
) VALUES (
	$1, $2, $3,
	$4, $5, $6, $7,
	$8, $9, $10, $11, $12,
	$13, $14, $15,
	$16, $17, $18,
	$19, $20, $21, $22,
	$23, $24, $25,
	$26, now()
)
ON CONFLICT (socket_cookie) DO UPDATE SET
	tuple_key          = EXCLUDED.tuple_key,
	hostname           = COALESCE(EXCLUDED.hostname, tcp_state_connections.hostname),
	client_ip          = EXCLUDED.client_ip,
	client_port        = EXCLUDED.client_port,
	server_ip          = EXCLUDED.server_ip,
	server_port        = EXCLUDED.server_port,
	start_time         = LEAST(COALESCE(tcp_state_connections.start_time, EXCLUDED.start_time), EXCLUDED.start_time),
	end_time           = GREATEST(COALESCE(tcp_state_connections.end_time, EXCLUDED.end_time), EXCLUDED.end_time),
	duration_ms        = EXCLUDED.duration_ms,
	state_result       = CASE
	                       WHEN EXCLUDED.state_result IS NULL OR EXCLUDED.state_result = 'in_progress'
	                       THEN tcp_state_connections.state_result
	                       ELSE EXCLUDED.state_result
	                     END,
	failure_reason     = COALESCE(EXCLUDED.failure_reason, tcp_state_connections.failure_reason),
	syn_sent_at        = COALESCE(tcp_state_connections.syn_sent_at,    EXCLUDED.syn_sent_at),
	syn_recv_at        = COALESCE(tcp_state_connections.syn_recv_at,    EXCLUDED.syn_recv_at),
	established_at     = COALESCE(tcp_state_connections.established_at, EXCLUDED.established_at),
	fin_wait1_at       = COALESCE(tcp_state_connections.fin_wait1_at,   EXCLUDED.fin_wait1_at),
	fin_wait2_at       = COALESCE(tcp_state_connections.fin_wait2_at,   EXCLUDED.fin_wait2_at),
	close_wait_at      = COALESCE(tcp_state_connections.close_wait_at,  EXCLUDED.close_wait_at),
	closing_at         = COALESCE(tcp_state_connections.closing_at,     EXCLUDED.closing_at),
	last_ack_at        = COALESCE(tcp_state_connections.last_ack_at,    EXCLUDED.last_ack_at),
	time_wait_at       = COALESCE(tcp_state_connections.time_wait_at,   EXCLUDED.time_wait_at),
	close_at           = COALESCE(tcp_state_connections.close_at,       EXCLUDED.close_at),
	tcp_state          = EXCLUDED.tcp_state,
	tcp_state_at       = EXCLUDED.tcp_state_at,
	direction          = COALESCE(EXCLUDED.direction, tcp_state_connections.direction),
	is_final           = EXCLUDED.is_final,
	updated_at         = now()
`

func tpRowArgs(r *pgRowTP) []any {
	return []any{
		r.SocketCookie, r.TupleKey, r.Hostname,
		r.ClientIP, r.ClientPort, r.ServerIP, r.ServerPort,
		r.StartTime, r.EndTime, r.DurationMs, r.StateResult, r.FailureReason,
		r.SynSentAt, r.SynRecvAt, r.EstablishedAt,
		r.FinWait1At, r.FinWait2At, r.CloseWaitAt,
		r.ClosingAt, r.LastAckAt, r.TimeWaitAt, r.CloseAt,
		r.TCPState, r.TCPStateAt, r.Direction,
		r.IsFinal,
	}
}

// ============================================================================
// Helpers: tuple_key, cookie synth, timeline lookups
// ============================================================================

func canonicalTupleKey(ipA string, portA uint16, ipB string, portB uint16) string {
	if ipA > ipB || (ipA == ipB && portA > portB) {
		ipA, ipB = ipB, ipA
		portA, portB = portB, portA
	}
	return fmt.Sprintf("%s:%d-%s:%d", ipA, portA, ipB, portB)
}

func synthCookieFromTuple(tupleKey string) int64 {
	var h uint64 = 5381
	for i := 0; i < len(tupleKey); i++ {
		h = h*33 + uint64(tupleKey[i])
	}
	return -int64(h&0x7fffffffffffffff) - 1
}

func firstTimeForTCStep(tc *TCAggregatedConnection, step string) *time.Time {
	if tc == nil {
		return nil
	}
	for _, s := range tc.Timeline {
		if s.Step == step {
			t := s.Time
			return &t
		}
	}
	return nil
}

func latestTCStep(tc *TCAggregatedConnection) (*string, *time.Time) {
	if tc == nil || len(tc.Timeline) == 0 {
		return nil, nil
	}
	for i := len(tc.Timeline) - 1; i >= 0; i-- {
		s := tc.Timeline[i]
		if s.Step == "TCP-SYN-REXMIT" || s.Step == "TCP-SYN-ACK-REXMIT" {
			continue
		}
		label := s.Step
		t := s.Time
		return &label, &t
	}
	s := tc.Timeline[len(tc.Timeline)-1]
	label := s.Step
	t := s.Time
	return &label, &t
}

func firstTimeForState(tp *TPAggregatedConnection, newState uint32) *time.Time {
	if tp == nil {
		return nil
	}
	for _, sc := range tp.StateHistory {
		if sc.NewState == newState {
			t := sc.Time
			return &t
		}
	}
	return nil
}

func directionFromTC(tc *TCAggregatedConnection) (*string, string, int, string, int) {
	if tc == nil || !tc.DirectionKnown {
		return nil, "", 0, "", 0
	}
	switch tc.DirectionSeen {
	case DIR_OUTBOUND:
		d := "outbound"
		return &d, tc.SrcIP, int(tc.SrcPort), tc.DestIP, int(tc.DestPort)
	case DIR_INBOUND:
		d := "inbound"
		return &d, tc.SrcIP, int(tc.SrcPort), tc.DestIP, int(tc.DestPort)
	}
	return nil, "", 0, "", 0
}

func directionFromTP(tp *TPAggregatedConnection) (*string, string, int, string, int) {
	if tp == nil || len(tp.StateHistory) == 0 {
		return nil, "", 0, "", 0
	}
	switch tp.StateHistory[0].NewState {
	case TCP_SYN_SENT:
		d := "outbound"
		return &d, tp.SrcIP, int(tp.SrcPort), tp.DestIP, int(tp.DestPort)
	case TCP_SYN_RECV:
		d := "inbound"
		return &d, tp.SrcIP, int(tp.SrcPort), tp.DestIP, int(tp.DestPort)
	}
	return nil, "", 0, "", 0
}

// ============================================================================
// AggregatedConnection -> pgRow
// ============================================================================

func buildTCRow(tc *TCAggregatedConnection, isFinal bool) *pgRowTC {
	if tc == nil {
		return nil
	}
	row := &pgRowTC{IsFinal: isFinal}
	row.Hostname = hostname()

	row.TupleKey = canonicalTupleKey(tc.SrcIP, tc.SrcPort, tc.DestIP, tc.DestPort)

	if tc.SocketCookie != 0 {
		row.SocketCookie = int64(tc.SocketCookie)
	} else {
		row.SocketCookie = synthCookieFromTuple(row.TupleKey)
	}

	if tc.Domain != "" {
		d := tc.Domain
		row.Domain = &d
	}
	if !tc.StartTime.IsZero() {
		t := tc.StartTime
		row.StartTime = &t
	}
	if !tc.LastPacket.IsZero() {
		t := tc.LastPacket
		row.EndTime = &t
	}
	if row.StartTime != nil && row.EndTime != nil && row.EndTime.After(*row.StartTime) {
		d := row.EndTime.Sub(*row.StartTime).Milliseconds()
		row.DurationMs = &d
	}

	var res string
	switch {
	case tc.IsFailed || tc.Result == RESULT_FAILED:
		res = "failed"
		if fr := failureReasonName(tc.FailureReason); fr != "" {
			row.FailureReason = &fr
		}
	case tc.Result == RESULT_SUCCESS:
		res = "success"
	default:
		res = "in_progress"
	}
	row.Result = &res

	if tc.TCPHandshakeMs > 0 {
		v := int(tc.TCPHandshakeMs)
		row.TCPHandshakeMs = &v
	}
	if tc.TCPRttMs > 0 {
		v := int(tc.TCPRttMs)
		row.TCPRttMs = &v
	}
	if tc.TLSHandshakeMs > 0 {
		v := int(tc.TLSHandshakeMs)
		row.TLSHandshakeMs = &v
	}
	if tc.TLSVersion > 0 {
		v := getTLSVersion(tc.TLSVersion)
		row.TLSVersion = &v
	}
	if tc.TTFBMs > 0 {
		v := int(tc.TTFBMs)
		row.TTFBMs = &v
	}
	if tc.TotalBytesSent > 0 {
		v := int64(tc.TotalBytesSent)
		row.BytesSent = &v
	}
	if tc.TotalBytesRcvd > 0 {
		v := int64(tc.TotalBytesRcvd)
		row.BytesReceived = &v
	}
	if tc.DataTransfers > 0 {
		v := tc.DataTransfers
		row.DataTransfers = &v
	}
	if tc.SYNRetransmits > 0 {
		v := int(tc.SYNRetransmits)
		row.SYNRetransmits = &v
	}
	if tc.RetransmitEvents > 0 {
		v := int(tc.RetransmitEvents)
		row.RetransmitEvents = &v
	}

	row.TCSynAt = firstTimeForTCStep(tc, "TCP-SYN")
	row.TCSynAckAt = firstTimeForTCStep(tc, "TCP-SYN-ACK")
	row.TCAckAt = firstTimeForTCStep(tc, "TCP-ACK")
	row.TCSynRexmitAt = firstTimeForTCStep(tc, "TCP-SYN-REXMIT")
	row.TCSynAckRexmitAt = firstTimeForTCStep(tc, "TCP-SYN-ACK-REXMIT")
	row.TLSClientHelloAt = firstTimeForTCStep(tc, "TLS-ClientHello")
	row.TLSServerHelloAt = firstTimeForTCStep(tc, "TLS-ServerHello")
	row.TLSCertificateAt = firstTimeForTCStep(tc, "TLS-Certificate")
	row.TLSFinishedAt = firstTimeForTCStep(tc, "TLS-Finished")
	row.TLSHandshakeDoneAt = firstTimeForTCStep(tc, "TLS-HandshakeDone")
	row.TCState, row.TCStateAt = latestTCStep(tc)

	dir, localIP, localPort, remoteIP, remotePort := directionFromTC(tc)
	if dir == nil {
		row.ClientIP, row.ClientPort = tc.SrcIP, int(tc.SrcPort)
		row.ServerIP, row.ServerPort = tc.DestIP, int(tc.DestPort)
	} else {
		if *dir == "outbound" {
			row.ClientIP, row.ClientPort = localIP, localPort
			row.ServerIP, row.ServerPort = remoteIP, remotePort
		} else {
			row.ClientIP, row.ClientPort = remoteIP, remotePort
			row.ServerIP, row.ServerPort = localIP, localPort
		}
		row.Direction = dir
	}

	if row.ClientIP == "" || row.ServerIP == "" {
		return nil
	}
	return row
}

func buildTPRow(tp *TPAggregatedConnection, isFinal bool) *pgRowTP {
	if tp == nil {
		return nil
	}
	row := &pgRowTP{IsFinal: isFinal}
	row.Hostname = hostname()

	row.TupleKey = canonicalTupleKey(tp.SrcIP, tp.SrcPort, tp.DestIP, tp.DestPort)

	if tp.SocketCookie != 0 {
		row.SocketCookie = int64(tp.SocketCookie)
	} else {
		row.SocketCookie = synthCookieFromTuple(row.TupleKey)
	}

	if !tp.CreatedTime.IsZero() {
		t := tp.CreatedTime
		row.StartTime = &t
	}
	if !tp.LastStateChange.IsZero() {
		t := tp.LastStateChange
		row.EndTime = &t
	}
	if row.StartTime != nil && row.EndTime != nil && row.EndTime.After(*row.StartTime) {
		d := row.EndTime.Sub(*row.StartTime).Milliseconds()
		row.DurationMs = &d
	}

	var st string
	switch tp.Result {
	case RESULT_SUCCESS:
		st = "success"
	case RESULT_FAILED:
		if tp.ObservedOnlyAtEnd {
			st = "unknown_observed_at_end"
		} else {
			st = "failed"
		}
	case RESULT_TIMEOUT:
		st = "timeout_forced_flush"
	default:
		st = "in_progress"
	}
	row.StateResult = &st

	if tp.FailureReason != 0 {
		if fr := failureReasonName(tp.FailureReason); fr != "" {
			row.FailureReason = &fr
		}
	}

	if tp.CurrentState != 0 {
		name := getTCPStateName(tp.CurrentState)
		row.TCPState = &name
		if !tp.LastStateChange.IsZero() {
			t := tp.LastStateChange
			row.TCPStateAt = &t
		}
	}

	row.SynSentAt = firstTimeForState(tp, TCP_SYN_SENT)
	row.SynRecvAt = firstTimeForState(tp, TCP_SYN_RECV)
	row.EstablishedAt = firstTimeForState(tp, TCP_ESTABLISHED)
	row.FinWait1At = firstTimeForState(tp, TCP_FIN_WAIT1)
	row.FinWait2At = firstTimeForState(tp, TCP_FIN_WAIT2)
	row.CloseWaitAt = firstTimeForState(tp, TCP_CLOSE_WAIT)
	row.ClosingAt = firstTimeForState(tp, TCP_CLOSING)
	row.LastAckAt = firstTimeForState(tp, TCP_LAST_ACK)
	row.TimeWaitAt = firstTimeForState(tp, TCP_TIME_WAIT)
	row.CloseAt = firstTimeForState(tp, TCP_CLOSE)

	dir, localIP, localPort, remoteIP, remotePort := directionFromTP(tp)
	if dir == nil {
		row.ClientIP, row.ClientPort = tp.SrcIP, int(tp.SrcPort)
		row.ServerIP, row.ServerPort = tp.DestIP, int(tp.DestPort)
	} else {
		if *dir == "outbound" {
			row.ClientIP, row.ClientPort = localIP, localPort
			row.ServerIP, row.ServerPort = remoteIP, remotePort
		} else {
			row.ClientIP, row.ClientPort = remoteIP, remotePort
			row.ServerIP, row.ServerPort = localIP, localPort
		}
		row.Direction = dir
	}

	if row.ClientIP == "" || row.ServerIP == "" {
		return nil
	}
	return row
}

// ============================================================================
// Conn string helpers
// ============================================================================

func buildPGConnString(host string, port int, user, pass, db, sslmode string) string {
	if sslmode == "" {
		sslmode = "disable"
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, pass, db, sslmode)
}

func redactConnString(s string) string {
	if i := strings.Index(s, "password="); i >= 0 {
		j := strings.Index(s[i:], " ")
		if j < 0 {
			return s[:i] + "password=***"
		}
		return s[:i] + "password=***" + s[i+j:]
	}
	return s
}
