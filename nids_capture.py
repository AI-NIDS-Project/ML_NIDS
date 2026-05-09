#!/usr/bin/env python3
"""
nids_capture.py - NetFlow v3 feature extractor for AI-NIDS
by Ka Shing Ng
===========================================================

Captures live network traffic (or reads pcap files) and outputs CSV rows
matching the 53-column NetFlow v3 features used by NF-UNSW-NB15-v2.

Each row represents one completed flow: unidirectional packet sequence
between a source and destination, aggregated bidirectionally by 5-tuple).

Example Usage:
    ## Live capture on interface (requires root/sudo)
    sudo python3 nids_capture.py -i eth0 -o flows.csv

    ## Offline: read a pcap file
    python3 nids_capture.py -i traffic.pcap -o flows.csv

    ## Stream to stdout (pipe into another tool)
    sudo python3 nids_capture.py -i wlan0

Dependencies: nfstream
"""

import struct
import csv
import sys
import argparse

from nfstream import NFStreamer, NFPlugin


## Constants

## TCP flag bitmask values (RFC 793 + RFC 3168)
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80

## nDPI L7 protocol name → numeric ID (subset of common protocols).
## Protocol number is zero if the protocol name isn't in the data.
NDPI_PROTO_MAP = {
    "Unknown": 0, "FTP_CONTROL": 1, "POP3": 2, "SMTP": 3, "IMAP": 4,
    "DNS": 5, "IPP": 6, "HTTP": 7, "MDNS": 8, "NTP": 9, "NetBIOS": 10,
    "NFS": 11, "SSDP": 12, "BGP": 13, "SNMP": 14, "XDMCP": 15,
    "SMBv1": 16, "Syslog": 17, "DHCP": 18, "PostgreSQL": 19, "MySQL": 20,
    "Hotmail": 21, "Direct_Download_Link": 22, "POPS": 23, "VMware": 24,
    "SMTPS": 25, "FBZERO": 26, "UBNTAC2": 27, "Kontiki": 28,
    "OpenVPN": 29, "IMAPS": 30, "TLS": 91, "SSH": 92, "QUIC": 188,
    "RDP": 88, "Telnet": 44, "TFTP": 71, "SIP": 100, "RTP": 87,
    "DTLS": 186, "WhatsApp": 142, "Zoom": 272, "Slack": 225,
    "Spotify": 156, "YouTube": 124, "Netflix": 133, "Dropbox": 132,
    "Google": 126, "Facebook": 119, "Twitter": 120, "Amazon": 178,
    "Apple": 140, "Microsoft": 212, "Cloudflare": 220, "GitHub": 203,
}

# Output column order - must match the NetFlow v3 feature CSV exactly.
OUTPUT_COLUMNS = [
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT",
    "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS", "TCP_FLAGS", "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS", "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL",
    "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES", "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
    "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE",
    "FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS",
    "SRC_TO_DST_IAT_MIN", "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG", "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN", "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG", "DST_TO_SRC_IAT_STDDEV",
]


## Packet header parsing helpers


def _parse_ipv4_ttl(ip_packet: bytes) -> int:
    """Extract TTL from IPv4 header (byte offset 8)."""
    if ip_packet and len(ip_packet) > 8:
        return ip_packet[8]
    return 0


def _ipv4_header_length(ip_packet: bytes) -> int:
    """IHL field (lower nibble of byte 0) × 4 = header length in bytes."""
    if ip_packet and len(ip_packet) > 0:
        return (ip_packet[0] & 0x0F) * 4
    return 20 


def _parse_tcp_window(ip_packet: bytes, ip_hdr_len: int) -> int:
    """Extract TCP window size (bytes 14-15 of TCP header, big-endian)."""
    offset = ip_hdr_len + 14
    if ip_packet and len(ip_packet) >= offset + 2:
        return struct.unpack_from("!H", ip_packet, offset)[0]
    return 0


def _parse_tcp_seq(ip_packet: bytes, ip_hdr_len: int) -> int:
    """Extract TCP sequence number (bytes 4-7 of TCP header)."""
    offset = ip_hdr_len + 4
    if ip_packet and len(ip_packet) >= offset + 4:
        return struct.unpack_from("!I", ip_packet, offset)[0]
    return 0


def _build_flag_byte(packet) -> int:
    """Combine individual bool flags from NFPacket into a single bitmask."""
    flags = 0
    if packet.fin: flags |= FLAG_FIN
    if packet.syn: flags |= FLAG_SYN
    if packet.rst: flags |= FLAG_RST
    if packet.psh: flags |= FLAG_PSH
    if packet.ack: flags |= FLAG_ACK
    if packet.urg: flags |= FLAG_URG
    if packet.ece: flags |= FLAG_ECE
    if packet.cwr: flags |= FLAG_CWR
    return flags


def _parse_dns(ip_packet: bytes, ip_hdr_len: int):
    """
    Parse DNS header from a UDP payload.
    Returns (query_id, query_type, ttl_answer) or (0, 0, 0) on failure.
    """
    ## UDP header is 8 bytes; DNS payload starts after that.
    dns_offset = ip_hdr_len + 8
    if not ip_packet or len(ip_packet) < dns_offset + 12:
        return 0, 0, 0

    try:
        ## DNS header: ID (2), Flags (2), QDCount (2), ANCount (2), ...
        txn_id, flags, qd_count, an_count = struct.unpack_from(
            "!HHHH", ip_packet, dns_offset
        )
        ## Parse the first question to get QTYPE.
        ## Skip QNAME: sequence of length-prefixed labels ending with 0x00.
        pos = dns_offset + 12
        while pos < len(ip_packet):
            label_len = ip_packet[pos]
            if label_len == 0:
                pos += 1 
                break
            pos += 1 + label_len
        else:
            return txn_id, 0, 0

        ## QTYPE (2 bytes) + QCLASS (2 bytes)
        if pos + 4 > len(ip_packet):
            return txn_id, 0, 0
        query_type = struct.unpack_from("!H", ip_packet, pos)[0]
        pos += 4  ## skip QTYPE + QCLASS

        ## Parse first answer record for TTL (only in responses: QR bit = 1).
        ttl_answer = 0
        is_response = (flags >> 15) & 1
        if is_response and an_count > 0 and pos + 12 <= len(ip_packet):
            ## Answer NAME is usually a pointer (2 bytes starting with 0xC0).
            if ip_packet[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                ## Walk labels (rare for answers, but handle it)
                while pos < len(ip_packet) and ip_packet[pos] != 0:
                    pos += 1 + ip_packet[pos]
                pos += 1

            ## TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
            if pos + 10 <= len(ip_packet):
                ttl_answer = struct.unpack_from("!I", ip_packet, pos + 4)[0]

        return txn_id, query_type, ttl_answer

    except (struct.error, IndexError):
        return 0, 0, 0


def _parse_ftp_reply_code(ip_packet: bytes, ip_hdr_len: int) -> int:
    """
    Extract FTP reply code from the first TCP payload bytes.
    FTP responses start with a 3-digit numeric code (e.g. "220 Welcome").
    """
    ## TCP data offset: upper nibble of byte 12 of TCP header × 4
    if not ip_packet or len(ip_packet) < ip_hdr_len + 13:
        return 0
    tcp_data_offset = ((ip_packet[ip_hdr_len + 12] >> 4) & 0x0F) * 4
    payload_start = ip_hdr_len + tcp_data_offset

    if len(ip_packet) < payload_start + 3:
        return 0

    try:
        first_three = ip_packet[payload_start:payload_start + 3].decode("ascii")
        if first_three.isdigit():
            return int(first_three)
    except (UnicodeDecodeError, ValueError):
        pass
    return 0


## NFPlugin - per-packet feature extraction

class NetFlowV3Plugin(NFPlugin):
    """
    Extracts the ~22 features that nfstream doesn't provide natively.

    Runs on every packet (on_init / on_update) and finalizes on flow
    expiry (on_expire). Features are stored as flow.udps.* attributes
    which nfstream includes in to_pandas() / to_csv() output.

    Features:
        - TCP flag bitmasks (cumulative OR per direction)
        - Min/Max TTL across all packets
        - Longest/Shortest raw packet size
        - Packet count by IP-size buckets (5 buckets)
        - Max TCP window per direction
        - TCP retransmitted bytes/packets per direction
        - ICMP type and code
        - DNS query ID, type, and answer TTL
        - FTP reply code
    """

    def on_init(self, packet, flow):
        """Called once when the first packet of a new flow arrives."""

        ## TCP flag bitmasks (cumulative OR)
        flags = _build_flag_byte(packet)
        flow.udps.tcp_flags = flags
        if packet.direction == 0:
            flow.udps.client_tcp_flags = flags
            flow.udps.server_tcp_flags = 0
        else:
            flow.udps.client_tcp_flags = 0
            flow.udps.server_tcp_flags = flags

        ## TTL
        ttl = _parse_ipv4_ttl(packet.ip_packet)
        flow.udps.min_ttl = ttl
        flow.udps.max_ttl = ttl

        ## Raw packet size extremes (link-layer)
        flow.udps.longest_pkt = packet.raw_size
        flow.udps.shortest_pkt = packet.raw_size

        ## Packet-size buckets (by IP-layer size)
        flow.udps.pkts_up_to_128 = 0
        flow.udps.pkts_128_to_256 = 0
        flow.udps.pkts_256_to_512 = 0
        flow.udps.pkts_512_to_1024 = 0
        flow.udps.pkts_1024_to_1514 = 0
        self._bucket_packet(packet, flow)

        ## Max TCP window per direction
        flow.udps.tcp_win_max_in = 0
        flow.udps.tcp_win_max_out = 0
        if packet.protocol == 6:  ## TCP
            ip_hdr_len = _ipv4_header_length(packet.ip_packet)
            win = _parse_tcp_window(packet.ip_packet, ip_hdr_len)
            if packet.direction == 0:
                flow.udps.tcp_win_max_in = win
            else:
                flow.udps.tcp_win_max_out = win

        ## TCP retransmission tracking 
        ## Here, we track the "next expected sequence number" per direction.
        ## A packet whose seq < next_expected is counted as a retransmit.
        flow.udps.retrans_in_bytes = 0
        flow.udps.retrans_in_pkts = 0
        flow.udps.retrans_out_bytes = 0
        flow.udps.retrans_out_pkts = 0
        flow.udps._next_seq_in = 0   ## src→dst expected next seq
        flow.udps._next_seq_out = 0  ## dst→src expected next seq
        if packet.protocol == 6:
            self._init_tcp_seq(packet, flow)

        ## ICMP
        flow.udps.icmp_type_combined = 0  ## type*256 + code
        flow.udps.icmp_ipv4_type = 0
        if packet.protocol == 1: 
            self._parse_icmp(packet, flow)

        ## DNS (first packet only for query ID/type)
        flow.udps.dns_query_id = 0
        flow.udps.dns_query_type = 0
        flow.udps.dns_ttl_answer = 0
        if packet.protocol == 17 and (packet.src_port == 53 or packet.dst_port == 53):
            self._parse_dns_packet(packet, flow)

        ## FTP (look at server→client responses on port 21)
        flow.udps.ftp_cmd_ret_code = 0
        if packet.protocol == 6 and (packet.src_port == 21 or packet.dst_port == 21):
            self._parse_ftp_packet(packet, flow)

    def on_update(self, packet, flow):
        """Called for every subsequent packet belonging to this flow."""

        ## TCP flags: cumulative OR
        flags = _build_flag_byte(packet)
        flow.udps.tcp_flags |= flags
        if packet.direction == 0:
            flow.udps.client_tcp_flags |= flags
        else:
            flow.udps.server_tcp_flags |= flags

        ## TTL
        ttl = _parse_ipv4_ttl(packet.ip_packet)
        if ttl > 0:
            if ttl < flow.udps.min_ttl or flow.udps.min_ttl == 0:
                flow.udps.min_ttl = ttl
            if ttl > flow.udps.max_ttl:
                flow.udps.max_ttl = ttl

        ## Raw packet size extremes
        if packet.raw_size > flow.udps.longest_pkt:
            flow.udps.longest_pkt = packet.raw_size
        if packet.raw_size < flow.udps.shortest_pkt:
            flow.udps.shortest_pkt = packet.raw_size

        ## Packet-size buckets
        self._bucket_packet(packet, flow)

        ## TCP window max
        if packet.protocol == 6:
            ip_hdr_len = _ipv4_header_length(packet.ip_packet)
            win = _parse_tcp_window(packet.ip_packet, ip_hdr_len)
            if packet.direction == 0:
                flow.udps.tcp_win_max_in = max(flow.udps.tcp_win_max_in, win)
            else:
                flow.udps.tcp_win_max_out = max(flow.udps.tcp_win_max_out, win)

        ## TCP retransmission detection
        if packet.protocol == 6:
            self._check_retransmission(packet, flow)

        ## ICMP (take first non-zero)
        if packet.protocol == 1 and flow.udps.icmp_type_combined == 0:
            self._parse_icmp(packet, flow)

        ## DNS (update answer TTL from responses)
        if packet.protocol == 17 and (packet.src_port == 53 or packet.dst_port == 53):
            self._parse_dns_packet(packet, flow)

        ## FTP (capture reply code if not yet found)
        if (packet.protocol == 6
                and flow.udps.ftp_cmd_ret_code == 0
                and (packet.src_port == 21 or packet.dst_port == 21)):
            self._parse_ftp_packet(packet, flow)

    ## Internal helpers

    @staticmethod
    def _bucket_packet(packet, flow):
        """Sort packet into one of 5 IP-size buckets."""
        size = packet.ip_size
        if size <= 128:
            flow.udps.pkts_up_to_128 += 1
        elif size <= 256:
            flow.udps.pkts_128_to_256 += 1
        elif size <= 512:
            flow.udps.pkts_256_to_512 += 1
        elif size <= 1024:
            flow.udps.pkts_512_to_1024 += 1
        else:
            flow.udps.pkts_1024_to_1514 += 1

    @staticmethod
    def _init_tcp_seq(packet, flow):
        """Set initial next-expected-seq from the first TCP packet."""
        ip_hdr_len = _ipv4_header_length(packet.ip_packet)
        seq = _parse_tcp_seq(packet.ip_packet, ip_hdr_len)
        ## next_expected = seq + payload_size (+ 1 if SYN or FIN)
        payload = packet.payload_size
        adjust = 1 if (packet.syn or packet.fin) else 0
        next_seq = (seq + payload + adjust) & 0xFFFFFFFF
        if packet.direction == 0:
            flow.udps._next_seq_in = next_seq
        else:
            flow.udps._next_seq_out = next_seq

    @staticmethod
    def _check_retransmission(packet, flow):
        """
        Simple retransmission heuristic: if the packet's TCP sequence
        number is behind the next expected, it's a retransmit.

        Limitation: doesn't handle seq wraparound or selective ACKs
        perfectly, but matches what most flow meters report.
        """
        ip_hdr_len = _ipv4_header_length(packet.ip_packet)
        seq = _parse_tcp_seq(packet.ip_packet, ip_hdr_len)
        payload = packet.payload_size
        adjust = 1 if (packet.syn or packet.fin) else 0

        if packet.direction == 0:
            expected = flow.udps._next_seq_in
            if payload > 0 and expected > 0 and seq < expected:
                flow.udps.retrans_in_pkts += 1
                flow.udps.retrans_in_bytes += packet.ip_size
            new_next = (seq + payload + adjust) & 0xFFFFFFFF
            if new_next > flow.udps._next_seq_in or flow.udps._next_seq_in == 0:
                flow.udps._next_seq_in = new_next
        else:
            expected = flow.udps._next_seq_out
            if payload > 0 and expected > 0 and seq < expected:
                flow.udps.retrans_out_pkts += 1
                flow.udps.retrans_out_bytes += packet.ip_size
            new_next = (seq + payload + adjust) & 0xFFFFFFFF
            if new_next > flow.udps._next_seq_out or flow.udps._next_seq_out == 0:
                flow.udps._next_seq_out = new_next

    @staticmethod
    def _parse_icmp(packet, flow):
        """Parse ICMP type and code from IP payload."""
        ip_hdr_len = _ipv4_header_length(packet.ip_packet)
        offset = ip_hdr_len
        if packet.ip_packet and len(packet.ip_packet) >= offset + 2:
            icmp_type = packet.ip_packet[offset]
            icmp_code = packet.ip_packet[offset + 1]
            flow.udps.icmp_type_combined = icmp_type * 256 + icmp_code
            flow.udps.icmp_ipv4_type = icmp_type

    @staticmethod
    def _parse_dns_packet(packet, flow):
        """Parse DNS fields; updates query ID/type on first query,
        and answer TTL when a response is seen."""
        ip_hdr_len = _ipv4_header_length(packet.ip_packet)
        txn_id, qtype, ttl_ans = _parse_dns(packet.ip_packet, ip_hdr_len)
        if flow.udps.dns_query_id == 0:
            flow.udps.dns_query_id = txn_id
        if flow.udps.dns_query_type == 0:
            flow.udps.dns_query_type = qtype
        if ttl_ans > 0 and flow.udps.dns_ttl_answer == 0:
            flow.udps.dns_ttl_answer = ttl_ans

    @staticmethod
    def _parse_ftp_packet(packet, flow):
        """Parse 3-digit FTP reply code from TCP payload on port 21."""
        ip_hdr_len = _ipv4_header_length(packet.ip_packet)
        code = _parse_ftp_reply_code(packet.ip_packet, ip_hdr_len)
        if code > 0:
            flow.udps.ftp_cmd_ret_code = code


## Flow to output row conversion

def _safe_div(numerator, denominator, default=0):
    """Division with zero-denominator protection."""
    return numerator / denominator if denominator else default


def _resolve_l7_proto(flow) -> int:
    """
    Map nfstream's application_name string to a numeric nDPI protocol ID.
    Falls back to 0 (Unknown) for unrecognized protocols.
    """
    name = getattr(flow, "application_name", "Unknown")
    return NDPI_PROTO_MAP.get(name, 0)


def flow_to_row(flow) -> dict:
    """
    Convert a completed nfstream NFlow object into a dict whose keys
    match the 53-column NetFlow v3 schema exactly.

    Combines three data sources:
        1. nfstream core attributes (IPs, ports, bytes, packets, timestamps)
        2. nfstream statistical_analysis attributes (IAT min/max/avg/stddev)
        3. Our NetFlowV3Plugin udps.* attributes (TTL, flags, etc.)
    """

    ## Durations with zero-guard for rate calculations
    dur_ms = flow.bidirectional_duration_ms
    dur_in_ms = flow.src2dst_duration_ms
    dur_out_ms = flow.dst2src_duration_ms

    return {
        ## Flow identification (5-tuple + L7)
        "IPV4_SRC_ADDR":              flow.src_ip,
        "IPV4_DST_ADDR":              flow.dst_ip,
        "L4_SRC_PORT":                flow.src_port,
        "L4_DST_PORT":                flow.dst_port,
        "PROTOCOL":                   flow.protocol,
        "L7_PROTO":                   _resolve_l7_proto(flow),

        ## Byte and packet counts (src→dst = IN, dst→src = OUT)
        "IN_BYTES":                   flow.src2dst_bytes,
        "OUT_BYTES":                  flow.dst2src_bytes,
        "IN_PKTS":                    flow.src2dst_packets,
        "OUT_PKTS":                   flow.dst2src_packets,

        ## Duration
        "FLOW_DURATION_MILLISECONDS": dur_ms,
        "DURATION_IN":                dur_in_ms,
        "DURATION_OUT":               dur_out_ms,

        ## TCP flags (from plugin)
        "TCP_FLAGS":                  flow.udps.tcp_flags,
        "CLIENT_TCP_FLAGS":           flow.udps.client_tcp_flags,
        "SERVER_TCP_FLAGS":           flow.udps.server_tcp_flags,

        ## TTL (from plugin)
        "MIN_TTL":                    flow.udps.min_ttl,
        "MAX_TTL":                    flow.udps.max_ttl,

        ## Packet sizes - raw (link layer) for longest/shortest,
        ## IP layer for min/max IP pkt len.
        "LONGEST_FLOW_PKT":          flow.udps.longest_pkt,
        "SHORTEST_FLOW_PKT":         flow.udps.shortest_pkt,
        "MIN_IP_PKT_LEN":            getattr(flow, "bidirectional_min_ps", 0),
        "MAX_IP_PKT_LEN":            getattr(flow, "bidirectional_max_ps", 0),

        ## Throughput / rate (derived from core fields)
        "SRC_TO_DST_SECOND_BYTES":   _safe_div(flow.src2dst_bytes * 1000, dur_in_ms),
        "DST_TO_SRC_SECOND_BYTES":   _safe_div(flow.dst2src_bytes * 1000, dur_out_ms),
        "SRC_TO_DST_AVG_THROUGHPUT": _safe_div(flow.src2dst_bytes * 8000, dur_in_ms),
        "DST_TO_SRC_AVG_THROUGHPUT": _safe_div(flow.dst2src_bytes * 8000, dur_out_ms),

        ## Retransmissions (from plugin)
        "RETRANSMITTED_IN_BYTES":    flow.udps.retrans_in_bytes,
        "RETRANSMITTED_IN_PKTS":     flow.udps.retrans_in_pkts,
        "RETRANSMITTED_OUT_BYTES":   flow.udps.retrans_out_bytes,
        "RETRANSMITTED_OUT_PKTS":    flow.udps.retrans_out_pkts,

        ## Packet size distribution buckets (from plugin)
        "NUM_PKTS_UP_TO_128_BYTES":  flow.udps.pkts_up_to_128,
        "NUM_PKTS_128_TO_256_BYTES": flow.udps.pkts_128_to_256,
        "NUM_PKTS_256_TO_512_BYTES": flow.udps.pkts_256_to_512,
        "NUM_PKTS_512_TO_1024_BYTES":flow.udps.pkts_512_to_1024,
        "NUM_PKTS_1024_TO_1514_BYTES":flow.udps.pkts_1024_to_1514,

        ## TCP window max per direction (from plugin)
        "TCP_WIN_MAX_IN":            flow.udps.tcp_win_max_in,
        "TCP_WIN_MAX_OUT":           flow.udps.tcp_win_max_out,

        ## ICMP (from plugin)
        "ICMP_TYPE":                 flow.udps.icmp_type_combined,
        "ICMP_IPV4_TYPE":            flow.udps.icmp_ipv4_type,

        ## DNS (from plugin)
        "DNS_QUERY_ID":              flow.udps.dns_query_id,
        "DNS_QUERY_TYPE":            flow.udps.dns_query_type,
        "DNS_TTL_ANSWER":            flow.udps.dns_ttl_answer,

        ## FTP (from plugin)
        "FTP_COMMAND_RET_CODE":      flow.udps.ftp_cmd_ret_code,

        ## Timestamps
        "FLOW_START_MILLISECONDS":   flow.bidirectional_first_seen_ms,
        "FLOW_END_MILLISECONDS":     flow.bidirectional_last_seen_ms,

        ## Inter-Arrival Time stats (from nfstream statistical_analysis)
        "SRC_TO_DST_IAT_MIN":       getattr(flow, "src2dst_min_piat_ms", 0),
        "SRC_TO_DST_IAT_MAX":       getattr(flow, "src2dst_max_piat_ms", 0),
        "SRC_TO_DST_IAT_AVG":       getattr(flow, "src2dst_mean_piat_ms", 0),
        "SRC_TO_DST_IAT_STDDEV":    getattr(flow, "src2dst_stddev_piat_ms", 0),
        "DST_TO_SRC_IAT_MIN":       getattr(flow, "dst2src_min_piat_ms", 0),
        "DST_TO_SRC_IAT_MAX":       getattr(flow, "dst2src_max_piat_ms", 0),
        "DST_TO_SRC_IAT_AVG":       getattr(flow, "dst2src_mean_piat_ms", 0),
        "DST_TO_SRC_IAT_STDDEV":    getattr(flow, "dst2src_stddev_piat_ms", 0),
    }


## Main entry point

def create_streamer(source: str, bpf_filter: str = None) -> NFStreamer:
    """
    Build an NFStreamer configured for NetFlow v3 feature extraction.

    Key settings:
        - accounting_mode=1 (IP layer) so MIN/MAX_IP_PKT_LEN use IP sizes
        - statistical_analysis=True for IAT and packet-size stats
        - n_dissections=20 for L7 protocol detection (nDPI)
        - snapshot_length=1536 to capture enough for header parsing
    """
    return NFStreamer(
        source=source,
        statistical_analysis=True,
        accounting_mode=1,
        n_dissections=20,
        promiscuous_mode=True,
        snapshot_length=1536,
        idle_timeout=120,
        active_timeout=1800,
        bpf_filter=bpf_filter,
        udps=NetFlowV3Plugin(),
    )


def run_capture(source: str, output_path: str = None, bpf_filter: str = None):
    """
    Main capture function. Reads flows from source (interface or pcap),
    Converts each to a 53-column row, and writes CSV.

    Arguments:
        source:      Network interface name ("eth0") or pcap file path.
        output_path: CSV output file path, or None for stdout.
        bpf_filter:  Optional BPF filter (e.g. "tcp port 80").
    """
    streamer = create_streamer(source, bpf_filter)

    out = open(output_path, "w", newline="") if output_path else sys.stdout
    writer = csv.DictWriter(out, fieldnames=OUTPUT_COLUMNS)
    writer.writeheader()

    flow_count = 0
    try:
        for flow in streamer:
            row = flow_to_row(flow)
            writer.writerow(row)
            flow_count += 1

            ## Progress indicator on stderr for long captures
            if flow_count % 1000 == 0:
                print(f"[nids_capture] {flow_count} flows exported...",
                      file=sys.stderr)

    except KeyboardInterrupt:
        print(f"\n[nids_capture] Stopped. {flow_count} flows written.",
              file=sys.stderr)
    finally:
        if output_path:
            out.close()
            print(f"[nids_capture] Output saved to {output_path}",
                  file=sys.stderr)

    return flow_count


def main():
    parser = argparse.ArgumentParser(
        description="Capture network flows and extract NetFlow v3 features "
                    "for AI-NIDS (matching NF-UNSW-NB15-v2 schema).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  sudo python3 nids_capture.py -i eth0 -o flows.csv\n"
               "  python3 nids_capture.py -i capture.pcap -o flows.csv\n"
               "  sudo python3 nids_capture.py -i wlan0 -f 'tcp' | head\n",
    )
    parser.add_argument(
        "-i", "--interface", required=True,
        help="Network interface (e.g. eth0, wlan0) or pcap file path.",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output CSV path. Omit to write to stdout.",
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help="BPF packet filter (e.g. 'tcp port 80', 'not port 22').",
    )
    args = parser.parse_args()

    count = run_capture(args.interface, args.output, args.filter)
    if count == 0:
        print("[nids_capture] Warning: no flows captured. Check permissions "
              "(sudo) and interface name.", file=sys.stderr)


if __name__ == "__main__":
    main()
