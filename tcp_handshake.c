//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define IPPROTO_TCP 6

// ---- TCP states ----
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11
#define TCP_NEW_SYN_RECV 12

// ---- TCP flags ----
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

// ---- TC event types ----
#define TC_EVENT_SYN_SENT           1
#define TC_EVENT_SYN_ACK_RCVD       2
#define TC_EVENT_HANDSHAKE_SUCCESS  3
#define TC_EVENT_DATA_SENT          4
#define TC_EVENT_DATA_RCVD          5
#define TC_EVENT_DATA_TRANSFER      6
#define TC_EVENT_SYN_RETRANSMIT     7
#define TC_EVENT_SYNACK_RETRANSMIT  8
#define TC_EVENT_HANDSHAKE_FAILED   9
#define TC_EVENT_HANDSHAKE_TIMEOUT  10
#define TC_EVENT_SYN_RCVD           11
#define TC_EVENT_SYN_ACK_SENT       12

// ---- TLS event types ----
#define TLS_EVENT_CLIENT_HELLO   20
#define TLS_EVENT_SERVER_HELLO   21
#define TLS_EVENT_CERTIFICATE    22
#define TLS_EVENT_FINISHED       23
#define TLS_EVENT_HANDSHAKE_DONE 24

// ---- Failure reasons ----
#define FAIL_NONE                    0
#define FAIL_RST                     1
#define FAIL_MAX_RETRANSMIT          2
#define FAIL_BAD_ACK                 3
#define FAIL_FIN_DURING_HANDSHAKE    4
#define FAIL_TIMEOUT                 5
#define FAIL_HANDSHAKE_ABORTED       7

// ---- Limits ----
#define MAX_SYN_RETRANSMITS     3
#define MAX_SYNACK_RETRANSMITS  3
#define MAX_DOMAIN_LEN          48
#define HANDSHAKE_STALE_NS      120000000000ULL

// Explicit upper bound for a single TLS extension, needed by the verifier.
#define MAX_TLS_EXT_LEN         512

// ---- Socket cookie fallback seed ----
#define COOKIE_FALLBACK_SEED    0x9E3779B97F4A7C15ULL

#define DIR_UNKNOWN   0
#define DIR_INBOUND   1
#define DIR_OUTBOUND  2

struct conn_key {
    __u32 ip1;
    __u32 ip2;
    __u16 port1;
    __u16 port2;
};

struct tc_conn_value {
    __u8  tc_scratch_state;
    __u8  retransmit_count;
    __u8  is_client;
    __u8  synack_retransmit_count;
    __u64 syn_time_ns;
    __u64 synack_time_ns;
    __u64 ack_time_ns;
    __u32 syn_seq;
    __u32 synack_seq;
    __u32 synack_ack;
    __u32 ack_seq;
    __u32 ack_ack;

    __u64 first_data_from_server_time_ns;
    __u64 first_data_from_client_time_ns;
    __u32 total_bytes_sent;
    __u32 total_bytes_rcvd;
    __u8  handshake_complete;
    __u8  _pad2[3];

    char  domain[MAX_DOMAIN_LEN];
    __u8  domain_detected;
    __u8  _pad3[3];

    __u64 tls_start_time_ns;
    __u64 tls_client_hello_time_ns;
    __u64 tls_server_hello_time_ns;
    __u64 tls_certificate_time_ns;
    __u64 tls_finished_time_ns;
    __u8  tls_state;
    __u8  tls_version;
    __u8  _pad4[6];

    __u64 socket_cookie;
};

struct tc_event {
    __u64 timestamp_ns;              // 0
    __u32 src_ip;                    // 8
    __u32 dest_ip;                   // 12
    __u16 src_port;                  // 16
    __u16 dest_port;                 // 18
    __u8  event_type;                // 20
    __u8  result;                    // 21
    __u8  is_retransmit;             // 22
    __u8  direction;                 // 23
    __u32 handshake_duration_ms;     // 24
    __u32 syn_to_synack_ms;          // 28
    __u32 data_to_first_byte_ms;     // 32
    __u32 data_transfer_duration_ms; // 36
    __u32 seq_num;                   // 40
    __u32 ack_num;                   // 44
    __u32 payload_len;               // 48
    __u32 retransmit_count;          // 52
    __u32 syn_seq;                   // 56
    __u32 synack_seq;                // 60
    __u32 synack_ack;                // 64
    __u32 ack_seq;                   // 68
    __u32 ack_ack;                   // 72
    __u32 total_bytes_sent;          // 76
    __u32 total_bytes_rcvd;          // 80
    __u32 tls_client_hello_ms;       // 84
    __u32 tls_server_hello_ms;       // 88
    __u32 tls_certificate_ms;        // 92
    __u32 tls_finished_ms;           // 96
    __u32 tls_total_ms;              // 100
    __u8  tls_version;               // 104
    __u8  _pad2[3];                  // 105
    char  domain[MAX_DOMAIN_LEN];    // 108
    __u64 socket_cookie;             // 156
};

struct tp_conn_value {
    __u32 old_state;
    __u32 new_state;
    __u64 state_change_ns;
    __u64 created_ns;
};

struct tp_event {
    __u64 timestamp_ns;
    __u64 skaddr;
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u32 old_state;
    __u32 new_state;
    __u32 result;
    __u64 created_ns;
    __u64 socket_cookie;
};

_Static_assert(sizeof(struct tc_event) == 168, "tc_event must be 168 bytes");
_Static_assert(sizeof(struct tp_event) == 56,  "tp_event must be 56 bytes");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} tc_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(struct conn_key));
    __uint(value_size, sizeof(struct tc_conn_value));
} tc_conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} tp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct tp_conn_value));
} tp_conn_map SEC(".maps");

static __always_inline __u32 ns_to_ms(__u64 ns) {
    return ns / 1000000;
}

static __always_inline __u64 fallback_cookie(__u32 src_ip, __u32 dst_ip,
                                              __u16 src_port, __u16 dst_port) {
    __u64 h = ((__u64)src_ip << 32) | (__u64)dst_ip;
    h ^= ((__u64)src_port << 48) | ((__u64)dst_port << 16);
    h ^= COOKIE_FALLBACK_SEED;
    return h | 1ULL;
}

static __always_inline struct conn_key get_consistent_conn_key(__u32 src_ip, __u32 dest_ip,
                                                                __u16 src_port, __u16 dest_port) {
    struct conn_key key = {};
    if (src_ip < dest_ip || (src_ip == dest_ip && src_port < dest_port)) {
        key.ip1 = src_ip;     key.ip2 = dest_ip;
        key.port1 = src_port; key.port2 = dest_port;
    } else {
        key.ip1 = dest_ip;    key.ip2 = src_ip;
        key.port1 = dest_port; key.port2 = src_port;
    }
    return key;
}

static __always_inline void reset_conn_full(struct tc_conn_value *conn) {
    conn->tc_scratch_state = 0;
    conn->retransmit_count = 0;
    conn->is_client = 0;
    conn->synack_retransmit_count = 0;
    conn->syn_time_ns = 0;
    conn->synack_time_ns = 0;
    conn->ack_time_ns = 0;
    conn->syn_seq = 0;
    conn->synack_seq = 0;
    conn->synack_ack = 0;
    conn->ack_seq = 0;
    conn->ack_ack = 0;
    conn->first_data_from_server_time_ns = 0;
    conn->first_data_from_client_time_ns = 0;
    conn->total_bytes_sent = 0;
    conn->total_bytes_rcvd = 0;
    conn->handshake_complete = 0;
    conn->domain_detected = 0;
    conn->tls_start_time_ns = 0;
    conn->tls_client_hello_time_ns = 0;
    conn->tls_server_hello_time_ns = 0;
    conn->tls_certificate_time_ns = 0;
    conn->tls_finished_time_ns = 0;
    conn->tls_state = 0;
    conn->tls_version = 0;
    conn->socket_cookie = 0;
    for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
        conn->domain[i] = 0;
    }
}

static __always_inline void reset_handshake_only(struct tc_conn_value *conn) {
    conn->tc_scratch_state = 0;
    conn->retransmit_count = 0;
    conn->synack_retransmit_count = 0;
    conn->is_client = 0;
    conn->syn_time_ns = 0;
    conn->synack_time_ns = 0;
    conn->ack_time_ns = 0;
    conn->syn_seq = 0;
    conn->synack_seq = 0;
    conn->synack_ack = 0;
    conn->ack_seq = 0;
    conn->ack_ack = 0;
    conn->handshake_complete = 0;
}

static __always_inline void emit_failure(struct __sk_buff *skb,
                                          struct tc_conn_value *conn,
                                          struct tc_event *e,
                                          __u64 current_time,
                                          __u8 reason) {
    e->event_type = TC_EVENT_HANDSHAKE_FAILED;
    e->result = reason;
    e->syn_seq = conn->syn_seq;
    e->synack_seq = conn->synack_seq;
    e->synack_ack = conn->synack_ack;
    e->retransmit_count = conn->retransmit_count;
    e->socket_cookie = conn->socket_cookie;
    if (conn->syn_time_ns != 0) {
        e->handshake_duration_ms = ns_to_ms(current_time - conn->syn_time_ns);
    }
    if (conn->syn_time_ns != 0 && conn->synack_time_ns != 0) {
        e->syn_to_synack_ms = ns_to_ms(conn->synack_time_ns - conn->syn_time_ns);
    }
    bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, e, sizeof(*e));

    reset_handshake_only(conn);
}

static __always_inline int is_hostname_char(unsigned char c) {
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '-') return 1;
    if (c == '.') return 1;
    if (c == '_') return 1;
    return 0;
}

// ============ HTTP DOMAIN DETECTION ============

static __always_inline int extract_http_domain(struct __sk_buff *skb,
                                                __u32 payload_offset,
                                                char *domain,
                                                int max_len) {
    for (int i = 0; i < 128; i++) {
        __u32 pos = payload_offset + i;
        if (pos + 6 > skb->len) break;

        unsigned char b[6];
        if (bpf_skb_load_bytes(skb, pos, b, 6) < 0) break;

        if ((b[0] == 'H' || b[0] == 'h') &&
            (b[1] == 'O' || b[1] == 'o') &&
            (b[2] == 'S' || b[2] == 's') &&
            (b[3] == 'T' || b[3] == 't') &&
            b[4] == ':' && b[5] == ' ') {

            int domain_pos = pos + 6;
            int dpos = 0;

            for (int w = 0; w < 4; w++) {
                unsigned char ws;
                if (bpf_skb_load_bytes(skb, domain_pos, &ws, 1) < 0) break;
                if (ws != ' ' && ws != '\t') break;
                domain_pos++;
            }

            for (int j = 0; j < MAX_DOMAIN_LEN - 1; j++) {
                if (domain_pos >= skb->len) break;
                unsigned char c;
                if (bpf_skb_load_bytes(skb, domain_pos, &c, 1) < 0) break;
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t' || c == ':') break;
                domain[dpos++] = c;
                domain_pos++;
            }

            int valid = 1;
            for (int k = 0; k < MAX_DOMAIN_LEN - 1; k++) {
                if (k >= dpos) break;
                if (!is_hostname_char((unsigned char)domain[k])) {
                    valid = 0;
                    break;
                }
            }
            if (!valid || dpos == 0) {
                domain[0] = '\0';
                return 0;
            }
            domain[dpos] = '\0';
            return dpos;
        }
    }
    return 0;
}

// ============ TLS SNI DOMAIN DETECTION ============

static __always_inline int extract_tls_sni_domain(struct __sk_buff *skb,
                                                   __u32 payload_offset,
                                                   char *domain,
                                                   int max_len) {
    domain[0] = '\0';

    if (payload_offset + 43 >= skb->len) {
        return 0;
    }

    unsigned char record_header[5];
    if (bpf_skb_load_bytes(skb, payload_offset, record_header, 5) < 0) {
        return 0;
    }

    if (record_header[0] != 0x16 || record_header[1] != 0x03) {
        return 0;
    }

    __u32 off = payload_offset + 5;

    unsigned char htype;
    if (bpf_skb_load_bytes(skb, off, &htype, 1) < 0 || htype != 0x01) {
        return 0;
    }

    off += 38;

    unsigned char sid_len;
    if (bpf_skb_load_bytes(skb, off, &sid_len, 1) < 0) {
        return 0;
    }
    off += 1 + (sid_len & 0x3F);

    __u16 cs_len;
    if (bpf_skb_load_bytes(skb, off, &cs_len, 2) < 0) {
        return 0;
    }
    cs_len = __builtin_bswap16(cs_len);
    off += 2 + (cs_len & 0x1FF);

    unsigned char comp_len;
    if (bpf_skb_load_bytes(skb, off, &comp_len, 1) < 0) {
        return 0;
    }
    off += 1 + (comp_len & 0x3F);

    __u16 ext_len;
    if (bpf_skb_load_bytes(skb, off, &ext_len, 2) < 0) {
        return 0;
    }
    ext_len = __builtin_bswap16(ext_len);
    off += 2;

    __u32 ext_start = off;
    __u32 final_domain_off = 0;
    __u16 final_sni_len = 0;

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (off + 4 > skb->len || off > ext_start + ext_len) {
            break;
        }

        __u16 ext_type, ext_len_val;
        if (bpf_skb_load_bytes(skb, off, &ext_type, 2) < 0) break;
        if (bpf_skb_load_bytes(skb, off + 2, &ext_len_val, 2) < 0) break;

        ext_type = __builtin_bswap16(ext_type);
        ext_len_val = __builtin_bswap16(ext_len_val);

        // Explicit verifier-friendly bounds on the extension length.
        // Without this, `off += 4 + ext_len_val` carries an unbounded
        // tnum and the verifier rejects subsequent bpf_skb_load_bytes
        // calls after a few iterations.
        if (ext_len_val > MAX_TLS_EXT_LEN) break;
        if (off + 4 + ext_len_val > skb->len) break;

        if (ext_type == 0) {
            __u32 sni_list_off = off + 4 + 2;

            unsigned char name_type;
            if (bpf_skb_load_bytes(skb, sni_list_off, &name_type, 1) == 0 && name_type == 0x00) {
                __u16 actual_sni_len;
                if (bpf_skb_load_bytes(skb, sni_list_off + 1, &actual_sni_len, 2) == 0) {
                    final_sni_len = __builtin_bswap16(actual_sni_len);
                    final_domain_off = sni_list_off + 3;
                }
            }
            break;
        }

        // Mask keeps ext_len_val within [0, MAX_TLS_EXT_LEN-1] as far as
        // the verifier is concerned, matching the runtime check above.
        off += 4 + (ext_len_val & 0x01FF);
    }

    if (final_sni_len > 0 && final_domain_off > 0) {
        char tmp_buf[MAX_DOMAIN_LEN] = {0};

        if (final_domain_off + MAX_DOMAIN_LEN <= skb->len) {
            if (bpf_skb_load_bytes(skb, final_domain_off, tmp_buf, MAX_DOMAIN_LEN) == 0) {
                #pragma unroll
                for (int j = 0; j < MAX_DOMAIN_LEN; j++) {
                    if (j < final_sni_len && j < (max_len - 1)) {
                        domain[j] = tmp_buf[j];
                    } else {
                        domain[j] = '\0';
                    }
                }
                return final_sni_len;
            }
        }
    }

    return 0;
}

// ============ TLS HANDSHAKE PARSER ============

static __always_inline int parse_tls_handshake(struct __sk_buff *skb,
                                                __u32 payload_offset,
                                                __u16 payload_len,
                                                struct tc_conn_value *conn,
                                                struct tc_event *e,
                                                __u64 current_time) {
    if (payload_len < 5) return 0;

    unsigned char record_header[5];
    if (bpf_skb_load_bytes(skb, payload_offset, record_header, 5) < 0) return 0;

    __u8 record_type = record_header[0];
    __u8 tls_major   = record_header[1];
    __u8 tls_minor   = record_header[2];
    if (tls_major != 0x03) return 0;

    if (record_type == 0x14 || record_type == 0x17) {
        if (conn->tls_state == 2 || conn->tls_state == 3) {
            conn->tls_finished_time_ns = current_time;
            conn->tls_state = 4;
            e->event_type = TLS_EVENT_HANDSHAKE_DONE;
            e->tls_finished_ms = ns_to_ms(current_time - conn->tls_start_time_ns);
            e->tls_total_ms = e->tls_finished_ms;
            e->tls_version = conn->tls_version;
            return 1;
        }
        return 0;
    }

    if (record_type != 0x16 || payload_len < 6) return 0;

    if (conn->tls_start_time_ns == 0) {
        conn->tls_start_time_ns = current_time;
        conn->tls_version = tls_minor;
    }

    __u32 off = payload_offset + 5;
    __u32 payload_end = payload_offset + payload_len;
    __u32 time_ms = ns_to_ms(current_time - conn->tls_start_time_ns);
    int event_type = 0;

    #pragma unroll
    for (int m = 0; m < 2; m++) {
        if (off + 4 > payload_end) break;

        unsigned char handshake_type;
        if (bpf_skb_load_bytes(skb, off, &handshake_type, 1) < 0) break;

        unsigned char len_bytes[3];
        if (bpf_skb_load_bytes(skb, off + 1, len_bytes, 3) < 0) break;

        __u32 msg_len = ((__u32)len_bytes[0] << 16) |
                        ((__u32)len_bytes[1] << 8) |
                        (__u32)len_bytes[2];

        if (msg_len > payload_len) break;
        if (msg_len > payload_end - off - 4) break;

        if (handshake_type == 0x01) {
            if (conn->tls_state < 1) {
                __u32 body_off = off + 4;
                __u16 actual_version_be;
                if (bpf_skb_load_bytes(skb, body_off, &actual_version_be, 2) == 0) {
                    __u16 actual_version = __builtin_bswap16(actual_version_be);
                    __u8 actual_minor = actual_version & 0xFF;
                    if ((actual_version >> 8) == 0x03 &&
                        actual_minor >= 0x01 && actual_minor <= 0x04) {
                        conn->tls_version = actual_minor;
                    }
                }
                conn->tls_client_hello_time_ns = current_time;
                conn->tls_state = 1;
                event_type = TLS_EVENT_CLIENT_HELLO;
                e->tls_client_hello_ms = time_ms;
            }
        } else if (handshake_type == 0x02) {
            if (conn->tls_state < 2) {
                conn->tls_server_hello_time_ns = current_time;
                conn->tls_state = 2;
                event_type = TLS_EVENT_SERVER_HELLO;
                e->tls_server_hello_ms = time_ms;
            }
        } else if (handshake_type == 0x0B) {
            if (conn->tls_state < 3) {
                conn->tls_certificate_time_ns = current_time;
                conn->tls_state = 3;
                event_type = TLS_EVENT_CERTIFICATE;
                e->tls_certificate_ms = time_ms;
            }
        } else if (handshake_type == 0x14) {
            conn->tls_finished_time_ns = current_time;
            conn->tls_state = 4;
            event_type = TLS_EVENT_FINISHED;
            e->tls_finished_ms = time_ms;
            e->tls_total_ms = time_ms;
            e->tls_version = conn->tls_version;
        }

        off += 4 + msg_len;
    }

    if (event_type > 0) {
        e->event_type = event_type;
        return 1;
    }
    return 0;
}

static __always_inline void detect_domain(struct __sk_buff *skb,
                                           __u32 payload_offset,
                                           __u16 payload_len,
                                           char *domain,
                                           int max_len) {
    domain[0] = '\0';
    if (payload_len == 0 || payload_offset + 5 > skb->len) return;

    unsigned char first_byte;
    if (bpf_skb_load_bytes(skb, payload_offset, &first_byte, 1) == 0) {
        if (first_byte == 0x16) {
            int sni_len = extract_tls_sni_domain(skb, payload_offset, domain, max_len);
            if (sni_len > 0) return;
        }
    }
    extract_http_domain(skb, payload_offset, domain, max_len);
}

// ============ TC MAIN ============

static __always_inline int process_packet(struct __sk_buff *skb, __u8 pkt_dir) {
    __u64 current_time = bpf_ktime_get_ns();

    unsigned char eth_bytes[2];
    if (bpf_skb_load_bytes(skb, 12, eth_bytes, 2) < 0) return 0;
    if (eth_bytes[0] != 0x08 || eth_bytes[1] != 0x00) return 0;

    unsigned char ip_protocol;
    if (bpf_skb_load_bytes(skb, 23, &ip_protocol, 1) < 0) return 0;
    if (ip_protocol != 6) return 0;

    unsigned char ip_ihl;
    if (bpf_skb_load_bytes(skb, 14, &ip_ihl, 1) < 0) return 0;
    __u8 ip_header_len = (ip_ihl & 0x0F) * 4;
    __u32 l4_offset = 14 + ip_header_len;

    __u32 src_ip, dest_ip;
    if (bpf_skb_load_bytes(skb, 26, &src_ip, 4) < 0) return 0;
    if (bpf_skb_load_bytes(skb, 30, &dest_ip, 4) < 0) return 0;

    __u16 src_port_be, dest_port_be;
    if (bpf_skb_load_bytes(skb, l4_offset, &src_port_be, 2) < 0) return 0;
    if (bpf_skb_load_bytes(skb, l4_offset + 2, &dest_port_be, 2) < 0) return 0;
    __u16 src_port = __builtin_bswap16(src_port_be);
    __u16 dest_port = __builtin_bswap16(dest_port_be);

    __u32 seq_num_be, ack_num_be;
    if (bpf_skb_load_bytes(skb, l4_offset + 4, &seq_num_be, 4) < 0) return 0;
    if (bpf_skb_load_bytes(skb, l4_offset + 8, &ack_num_be, 4) < 0) return 0;
    __u32 seq_num = __builtin_bswap32(seq_num_be);
    __u32 ack_num = __builtin_bswap32(ack_num_be);

    __u8 tcp_flags;
    if (bpf_skb_load_bytes(skb, l4_offset + 13, &tcp_flags, 1) < 0) return 0;

    __u8 tcp_data_offset;
    if (bpf_skb_load_bytes(skb, l4_offset + 12, &tcp_data_offset, 1) < 0) return 0;
    __u8 tcp_header_len = ((tcp_data_offset >> 4) & 0x0F) * 4;

    __u16 payload_len = 0;
    if (skb->len >= l4_offset + tcp_header_len) {
        payload_len = skb->len - l4_offset - tcp_header_len;
    }

    struct conn_key conn_key = get_consistent_conn_key(src_ip, dest_ip, src_port, dest_port);

    struct tc_conn_value *conn = bpf_map_lookup_elem(&tc_conn_map, &conn_key);
    if (!conn) {
        // BPF_NOEXIST: if two cores race here, only one wins the insert.
        // The loser still gets a valid pointer on the follow-up lookup.
        struct tc_conn_value new_conn = {};
        bpf_map_update_elem(&tc_conn_map, &conn_key, &new_conn, BPF_NOEXIST);
        conn = bpf_map_lookup_elem(&tc_conn_map, &conn_key);
        if (!conn) return 0;
    }

    __u64 current_cookie = bpf_get_socket_cookie(skb);
    if (current_cookie == 0) {
        current_cookie = fallback_cookie(src_ip, dest_ip, src_port, dest_port);
    }

    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        if (conn->tc_scratch_state != 0) {
            int cookie_changed = (conn->socket_cookie != 0 &&
                                  conn->socket_cookie != current_cookie);
            int same_handshake =
                ((conn->tc_scratch_state == TCP_SYN_SENT ||
                  conn->tc_scratch_state == TCP_SYN_RECV) &&
                 conn->syn_seq == seq_num);
            __u64 elapsed = (conn->syn_time_ns != 0)
                              ? (current_time - conn->syn_time_ns)
                              : (HANDSHAKE_STALE_NS + 1);
            if (cookie_changed || !same_handshake || elapsed > HANDSHAKE_STALE_NS) {
                reset_conn_full(conn);
            }
        }
    }

    if (conn->socket_cookie == 0) {
        conn->socket_cookie = current_cookie;
    }

    struct tc_event e = {};
    e.timestamp_ns = current_time;
    e.src_ip = src_ip;
    e.dest_ip = dest_ip;
    e.src_port = src_port;
    e.dest_port = dest_port;
    e.seq_num = seq_num;
    e.ack_num = ack_num;
    e.payload_len = payload_len;
    e.retransmit_count = conn->retransmit_count;
    e.result = FAIL_NONE;
    e.is_retransmit = 0;
    e.direction = pkt_dir;
    e.socket_cookie = conn->socket_cookie;

    __u32 payload_http_offset = l4_offset + tcp_header_len;

    if (tcp_flags & TCP_FLAG_RST) {
        if (conn->tc_scratch_state == TCP_SYN_SENT ||
            conn->tc_scratch_state == TCP_SYN_RECV) {
            emit_failure(skb, conn, &e, current_time, FAIL_RST);
            return 0;
        }
        if (conn->handshake_complete == 1) {
            conn->handshake_complete = 0;
            conn->tc_scratch_state = 0;
        }
        return 0;
    }

    if ((tcp_flags & TCP_FLAG_FIN) && conn->handshake_complete == 0 &&
        (conn->tc_scratch_state == TCP_SYN_SENT ||
         conn->tc_scratch_state == TCP_SYN_RECV)) {
        emit_failure(skb, conn, &e, current_time, FAIL_FIN_DURING_HANDSHAKE);
        return 0;
    }

    if (payload_len > 0) {
        parse_tls_handshake(skb, payload_http_offset, payload_len, conn, &e, current_time);
    }

    if (payload_len > 0 && conn->domain_detected == 0) {
        e.domain[0] = '\0';
        detect_domain(skb, payload_http_offset, payload_len, e.domain, MAX_DOMAIN_LEN);
        if (e.domain[0] != '\0') {
            e.domain[MAX_DOMAIN_LEN - 1] = '\0';
            #pragma unroll
            for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
                conn->domain[i] = e.domain[i];
            }
            conn->domain_detected = 1;
        }
    } else {
        #pragma unroll
        for (int i = 0; i < MAX_DOMAIN_LEN; i++) {
            e.domain[i] = conn->domain[i];
        }
    }
    e.domain[MAX_DOMAIN_LEN - 1] = '\0';

    if (e.event_type >= TLS_EVENT_CLIENT_HELLO &&
        e.event_type <= TLS_EVENT_HANDSHAKE_DONE) {
        bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    }

    // ================================================================
    // SYN handling — split by direction
    // ================================================================
    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        if (conn->tc_scratch_state == 0) {
            conn->syn_time_ns = current_time;
            conn->syn_seq = seq_num;
            conn->retransmit_count = 0;
            conn->synack_retransmit_count = 0;

            if (pkt_dir == DIR_OUTBOUND) {
                conn->tc_scratch_state = TCP_SYN_SENT;
                conn->is_client = 1;
                e.event_type = TC_EVENT_SYN_SENT;
            } else {
                conn->tc_scratch_state = TCP_SYN_RECV;
                conn->is_client = 0;
                e.event_type = TC_EVENT_SYN_RCVD;
            }
            e.syn_seq = seq_num;
            bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
            return 0;
        }
        else if ((conn->tc_scratch_state == TCP_SYN_SENT ||
                  conn->tc_scratch_state == TCP_SYN_RECV) &&
                 conn->syn_seq == seq_num) {
            conn->retransmit_count++;
            e.event_type = TC_EVENT_SYN_RETRANSMIT;
            e.is_retransmit = 1;
            e.syn_seq = seq_num;
            e.retransmit_count = conn->retransmit_count;
            bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
            if (conn->retransmit_count >= MAX_SYN_RETRANSMITS) {
                emit_failure(skb, conn, &e, current_time, FAIL_MAX_RETRANSMIT);
            }
            return 0;
        }
    }

    // ================================================================
    // SYN-ACK handling — split by direction
    // ================================================================
    if ((tcp_flags & TCP_FLAG_SYN) && (tcp_flags & TCP_FLAG_ACK)) {
        if (pkt_dir == DIR_INBOUND) {
            // Inbound SYN-ACK: we are the client
            if (conn->tc_scratch_state == TCP_SYN_SENT) {
                if (ack_num == conn->syn_seq + 1) {
                    conn->tc_scratch_state = TCP_SYN_RECV;
                    conn->synack_time_ns = current_time;
                    conn->synack_seq = seq_num;
                    conn->synack_ack = ack_num;
                    conn->synack_retransmit_count = 0;

                    e.event_type = TC_EVENT_SYN_ACK_RCVD;
                    e.synack_seq = seq_num;
                    e.synack_ack = ack_num;
                    e.syn_seq = conn->syn_seq;
                    e.syn_to_synack_ms = ns_to_ms(current_time - conn->syn_time_ns);
                    bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
                    return 0;
                } else {
                    emit_failure(skb, conn, &e, current_time, FAIL_BAD_ACK);
                    return 0;
                }
            }
            else if (conn->tc_scratch_state == TCP_SYN_RECV &&
                     conn->synack_seq == seq_num &&
                     ack_num == conn->syn_seq + 1) {
                conn->synack_retransmit_count++;
                e.event_type = TC_EVENT_SYNACK_RETRANSMIT;
                e.is_retransmit = 1;
                e.synack_seq = seq_num;
                e.synack_ack = ack_num;
                e.syn_seq = conn->syn_seq;
                bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
                if (conn->synack_retransmit_count >= MAX_SYNACK_RETRANSMITS) {
                    emit_failure(skb, conn, &e, current_time, FAIL_MAX_RETRANSMIT);
                }
                return 0;
            }
        } else {
            // Outbound SYN-ACK: we are the server
            if (conn->tc_scratch_state == TCP_SYN_RECV) {
                conn->synack_time_ns = current_time;
                conn->synack_seq = seq_num;
                conn->synack_ack = ack_num;

                e.event_type = TC_EVENT_SYN_ACK_SENT;
                e.synack_seq = seq_num;
                e.synack_ack = ack_num;
                e.syn_seq = conn->syn_seq;
                e.syn_to_synack_ms = ns_to_ms(current_time - conn->syn_time_ns);
                bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
                return 0;
            }
        }
    }

    // Mid-stream adoption: data on a connection whose handshake we never saw.
    if (conn->tc_scratch_state == 0 && payload_len > 0 &&
        !(tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_FIN) &&
        !(tcp_flags & TCP_FLAG_RST)) {
        conn->tc_scratch_state = TCP_ESTABLISHED;
        conn->handshake_complete = 1;
        conn->ack_time_ns = current_time;
    }

    // ================================================================
    // Pure ACK closes the handshake (either role)
    // ================================================================
    if ((tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & TCP_FLAG_SYN) && payload_len == 0) {
        if (conn->tc_scratch_state == TCP_SYN_RECV) {
            if (ack_num == conn->synack_seq + 1) {
                conn->tc_scratch_state = TCP_ESTABLISHED;
                conn->ack_time_ns = current_time;
                conn->ack_seq = seq_num;
                conn->ack_ack = ack_num;
                conn->handshake_complete = 1;

                e.event_type = TC_EVENT_HANDSHAKE_SUCCESS;
                e.syn_seq = conn->syn_seq;
                e.synack_seq = conn->synack_seq;
                e.synack_ack = conn->synack_ack;
                e.ack_seq = seq_num;
                e.ack_ack = ack_num;
                e.handshake_duration_ms = ns_to_ms(current_time - conn->syn_time_ns);
                e.syn_to_synack_ms = ns_to_ms(conn->synack_time_ns - conn->syn_time_ns);
                bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
                return 0;
            } else {
                emit_failure(skb, conn, &e, current_time, FAIL_BAD_ACK);
                return 0;
            }
        }
    }

    // ================================================================
    // Handshake completion when the third packet carries data
    //
    // The pure-ACK branch above requires payload_len == 0. If the
    // client's third handshake packet has data attached (TCP Fast Open
    // or a coalesced write), we never reach it. Detect the same
    // ACK-with-payload pattern here and complete the handshake before
    // the data-accounting block runs.
    // ================================================================
    if (payload_len > 0 &&
        conn->tc_scratch_state == TCP_SYN_RECV &&
        (tcp_flags & TCP_FLAG_ACK) && !(tcp_flags & TCP_FLAG_SYN) &&
        conn->synack_seq != 0) {
        if (ack_num == conn->synack_seq + 1) {
            conn->tc_scratch_state = TCP_ESTABLISHED;
            conn->ack_time_ns = current_time;
            conn->ack_seq = seq_num;
            conn->ack_ack = ack_num;
            conn->handshake_complete = 1;

            e.event_type = TC_EVENT_HANDSHAKE_SUCCESS;
            e.syn_seq = conn->syn_seq;
            e.synack_seq = conn->synack_seq;
            e.synack_ack = conn->synack_ack;
            e.ack_seq = seq_num;
            e.ack_ack = ack_num;
            e.handshake_duration_ms = ns_to_ms(current_time - conn->syn_time_ns);
            e.syn_to_synack_ms = ns_to_ms(conn->synack_time_ns - conn->syn_time_ns);
            bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

            // No return — fall through so the payload is accounted below.
        }
    }

    // ================================================================
    // Data transfer accounting
    // ================================================================
    if (payload_len > 0 && conn->handshake_complete == 1) {
        if (e.event_type >= TLS_EVENT_CLIENT_HELLO &&
            e.event_type <= TLS_EVENT_HANDSHAKE_DONE) {
            return 0;
        }

        if (pkt_dir == DIR_OUTBOUND) {
            conn->total_bytes_sent += payload_len;
            e.event_type = TC_EVENT_DATA_SENT;
            e.total_bytes_sent = conn->total_bytes_sent;
            bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
        }
        if (pkt_dir == DIR_INBOUND) {
            conn->total_bytes_rcvd += payload_len;
            if (conn->first_data_from_server_time_ns == 0) {
                conn->first_data_from_server_time_ns = current_time;
                e.event_type = TC_EVENT_DATA_RCVD;
                e.data_to_first_byte_ms = ns_to_ms(current_time - conn->ack_time_ns);
                e.total_bytes_rcvd = conn->total_bytes_rcvd;
                bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
            } else {
                e.event_type = TC_EVENT_DATA_TRANSFER;
                e.data_transfer_duration_ms =
                    ns_to_ms(current_time - conn->first_data_from_server_time_ns);
                e.total_bytes_rcvd = conn->total_bytes_rcvd;
                bpf_perf_event_output(skb, &tc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
            }
        }
    }

    return 0;
}

SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) { return process_packet(skb, DIR_INBOUND); }

SEC("tc")
int egress_prog_func(struct __sk_buff *skb) { return process_packet(skb, DIR_OUTBOUND); }

// ============ TRACEPOINT ============

struct inet_sock_set_state_args {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    __u8  common_preempt_lazy_count;
    __u8  _pad0[7];

    __u64 skaddr;
    __s32 oldstate;
    __s32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct inet_sock_set_state_args *ctx) {
    if (ctx->family != 2) return 0;
    // bpf_printk("tp: skaddr=0x%llx sport=%d dport=%d old=%d new=%d\n",
    //         ctx->skaddr, ctx->sport, ctx->dport,
    //         ctx->oldstate, ctx->newstate);
    // Drop synthetic states the kernel uses internally.
    // Keep LISTEN → SYN_RECV so we can observe server-side handshake start.
    if (ctx->newstate == TCP_NEW_SYN_RECV) return 0;
    if (ctx->oldstate == TCP_NEW_SYN_RECV) return 0;
    if (ctx->newstate == TCP_LISTEN) return 0;

    __u64 skaddr = ctx->skaddr;
    __u64 now = bpf_ktime_get_ns();

    struct tp_conn_value *existing = bpf_map_lookup_elem(&tp_conn_map, &skaddr);
    struct tp_conn_value new_v = {};

    __u32 prev_state = 0;
    __u64 created_ns = now;

    if (existing) {
        new_v = *existing;
        prev_state = existing->new_state;
        created_ns = existing->created_ns;
    }

    new_v.old_state = prev_state;
    new_v.new_state = ctx->newstate;
    new_v.state_change_ns = now;
    new_v.created_ns = created_ns;
    bpf_map_update_elem(&tp_conn_map, &skaddr, &new_v, BPF_ANY);

    struct tp_event e = {};
    e.timestamp_ns = now;
    e.skaddr = skaddr;

    __u32 saddr = 0, daddr = 0;
    __builtin_memcpy(&saddr, ctx->saddr, 4);
    __builtin_memcpy(&daddr, ctx->daddr, 4);
    e.src_ip = saddr;
    e.dest_ip = daddr;

    // Convert tracepoint ports to host byte order so they match the
    // TC side, which already calls __builtin_bswap16 after loading.
    //e.src_port = __builtin_bswap16(ctx->sport);
    //e.dest_port = __builtin_bswap16(ctx->dport);
    e.src_port = ctx->sport;
    e.dest_port = ctx->dport;

    e.old_state = prev_state;
    e.new_state = ctx->newstate;
    e.created_ns = created_ns;
    e.socket_cookie = (__u64)ctx->skaddr ^ created_ns;

    if (ctx->newstate == TCP_CLOSE || ctx->newstate == TCP_TIME_WAIT) {
        if (prev_state == TCP_SYN_SENT || prev_state == TCP_SYN_RECV) {
            e.result = FAIL_HANDSHAKE_ABORTED;
        } else {
            e.result = FAIL_NONE;
        }
    } else {
        e.result = FAIL_NONE;
    }

    bpf_perf_event_output(ctx, &tp_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    if (ctx->newstate == TCP_CLOSE || ctx->newstate == TCP_TIME_WAIT) {
        bpf_map_delete_elem(&tp_conn_map, &skaddr);
    }
    return 0;
}