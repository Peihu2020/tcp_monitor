-- ============================================================================
-- TCP Monitor schema
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TC side: one row per connection observed on the wire.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tcp_tc_connections (
    socket_cookie       BIGINT      PRIMARY KEY,
    tuple_key           TEXT        NOT NULL,

    hostname            TEXT        NOT NULL,

    client_ip           INET        NOT NULL,
    client_port         INTEGER     NOT NULL,
    server_ip           INET        NOT NULL,
    server_port         INTEGER     NOT NULL,

    domain              TEXT,

    start_time          TIMESTAMPTZ,
    end_time            TIMESTAMPTZ,
    duration_ms         BIGINT,

    result              TEXT,
    failure_reason      TEXT,

    tcp_handshake_ms    INTEGER,
    tcp_rtt_ms          INTEGER,
    tls_handshake_ms    INTEGER,
    tls_version         TEXT,
    ttfb_ms             INTEGER,

    bytes_sent          BIGINT,
    bytes_received      BIGINT,
    data_transfers      INTEGER,

    syn_retransmits     INTEGER,
    retransmit_events   INTEGER,

    tc_syn_at              TIMESTAMPTZ,
    tc_syn_ack_at          TIMESTAMPTZ,
    tc_ack_at              TIMESTAMPTZ,
    tc_syn_rexmit_at       TIMESTAMPTZ,
    tc_synack_rexmit_at    TIMESTAMPTZ,

    tls_client_hello_at    TIMESTAMPTZ,
    tls_server_hello_at    TIMESTAMPTZ,
    tls_certificate_at     TIMESTAMPTZ,
    tls_finished_at        TIMESTAMPTZ,
    tls_handshake_done_at  TIMESTAMPTZ,

    tc_state            TEXT,
    tc_state_at         TIMESTAMPTZ,

    direction           TEXT,

    is_final            BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tc_tuple_key   ON tcp_tc_connections (tuple_key);
CREATE INDEX IF NOT EXISTS idx_tc_start_time  ON tcp_tc_connections (start_time DESC);
CREATE INDEX IF NOT EXISTS idx_tc_client_ip   ON tcp_tc_connections (client_ip);
CREATE INDEX IF NOT EXISTS idx_tc_server_ip   ON tcp_tc_connections (server_ip);
CREATE INDEX IF NOT EXISTS idx_tc_is_final    ON tcp_tc_connections (is_final) WHERE is_final;

-- ----------------------------------------------------------------------------
-- TP side: one row per kernel socket (inet_sock_set_state).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tcp_state_connections (
    socket_cookie       BIGINT      PRIMARY KEY,
    tuple_key           TEXT        NOT NULL,

    hostname            TEXT        NOT NULL,

    client_ip           INET        NOT NULL,
    client_port         INTEGER     NOT NULL,
    server_ip           INET        NOT NULL,
    server_port         INTEGER     NOT NULL,

    start_time          TIMESTAMPTZ,
    end_time            TIMESTAMPTZ,
    duration_ms         BIGINT,

    state_result        TEXT,
    failure_reason      TEXT,

    syn_sent_at         TIMESTAMPTZ,
    syn_recv_at         TIMESTAMPTZ,
    established_at      TIMESTAMPTZ,
    fin_wait1_at        TIMESTAMPTZ,
    fin_wait2_at        TIMESTAMPTZ,
    close_wait_at       TIMESTAMPTZ,
    closing_at          TIMESTAMPTZ,
    last_ack_at         TIMESTAMPTZ,
    time_wait_at        TIMESTAMPTZ,
    close_at            TIMESTAMPTZ,

    tcp_state           TEXT,
    tcp_state_at        TIMESTAMPTZ,

    direction           TEXT,

    is_final            BOOLEAN     NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tp_tuple_key   ON tcp_state_connections (tuple_key);
CREATE INDEX IF NOT EXISTS idx_tp_start_time  ON tcp_state_connections (start_time DESC);
CREATE INDEX IF NOT EXISTS idx_tp_client_ip   ON tcp_state_connections (client_ip);
CREATE INDEX IF NOT EXISTS idx_tp_server_ip   ON tcp_state_connections (server_ip);
CREATE INDEX IF NOT EXISTS idx_tp_is_final    ON tcp_state_connections (is_final) WHERE is_final;

-- ----------------------------------------------------------------------------
-- Merged view: FULL OUTER JOIN on tuple_key.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW tcp_connections_merged AS
SELECT
    CASE
        WHEN tc.socket_cookie IS NULL THEN 'tp_only'
        WHEN tp.socket_cookie IS NULL THEN 'tc_only'
        ELSE 'matched'
    END                                            AS merge_status,

    COALESCE(tc.socket_cookie, tp.socket_cookie)   AS socket_cookie,
    COALESCE(tc.tuple_key,    tp.tuple_key)        AS tuple_key,

    COALESCE(tc.hostname, tp.hostname)             AS hostname,

    COALESCE(tc.client_ip,   tp.client_ip)         AS client_ip,
    COALESCE(tc.client_port, tp.client_port)       AS client_port,
    COALESCE(tc.server_ip,   tp.server_ip)         AS server_ip,
    COALESCE(tc.server_port, tp.server_port)       AS server_port,

    tc.domain,

    -- time window: union of both sides
    LEAST(tc.start_time, tp.start_time)            AS start_time,
    GREATEST(tc.end_time, tp.end_time)             AS end_time,
    EXTRACT(EPOCH FROM (
        GREATEST(tc.end_time, tp.end_time)
        - LEAST(tc.start_time, tp.start_time)
    )) * 1000                                      AS duration_ms,

    COALESCE(tc.direction, tp.direction)           AS direction,

    tc.result,
    tc.failure_reason                              AS tc_failure_reason,
    tp.failure_reason                              AS tp_failure_reason,

    tc.tcp_handshake_ms,
    tc.tcp_rtt_ms,
    tc.tls_handshake_ms,
    tc.tls_version,
    tc.ttfb_ms,
    tc.bytes_sent,
    tc.bytes_received,
    tc.data_transfers,
    tc.syn_retransmits,
    tc.retransmit_events,

    tc.tc_syn_at,
    tc.tc_syn_ack_at,
    tc.tc_ack_at,
    tc.tc_syn_rexmit_at,
    tc.tc_synack_rexmit_at,

    tc.tls_client_hello_at,
    tc.tls_server_hello_at,
    tc.tls_certificate_at,
    tc.tls_finished_at,
    tc.tls_handshake_done_at,

    tc.tc_state,
    tc.tc_state_at,

    tp.state_result,
    tp.syn_sent_at,
    tp.syn_recv_at,
    tp.established_at,
    tp.fin_wait1_at,
    tp.fin_wait2_at,
    tp.close_wait_at,
    tp.closing_at,
    tp.last_ack_at,
    tp.time_wait_at,
    tp.close_at,
    tp.tcp_state,
    tp.tcp_state_at,

    (COALESCE(tc.is_final, FALSE) OR COALESCE(tp.is_final, FALSE)) AS is_final,
    GREATEST(tc.updated_at, tp.updated_at)         AS updated_at
FROM tcp_tc_connections tc
FULL OUTER JOIN tcp_state_connections tp
    ON tc.tuple_key = tp.tuple_key;