# PCAP-to-flow method

Implemented in `src/pqdl/pcap.py` (`extract_connections`), driven by `scripts/pcaps_to_flows.py`, which writes
`data/flows/lab_flows.csv` (git-ignored, `source = "pq_lab"`). Input: our own captures of the lab server's
TCP port 4433 (see `lab/README.md`). Only TCP headers, sizes, timing and the cleartext TLS record headers and
ServerHello are used. Nothing is decrypted (AGENTS.md rule 4).

## Connections

- A connection **starts at each client SYN** (SYN without ACK) and **ends at the next client SYN on the same
  4-tuple** or at the end of the file. Source-port reuse therefore never merges connections (the lossy
  first mini-run showed the client reusing ports within seconds). A SYN with the same initial sequence number
  as the current connection is a retransmitted SYN, not a new connection.
- FIN/RST mark a connection `closed` but do not end it; trailing ACKs still count toward `flow_duration`.
- TCP packets of a tuple with no SYN seen are ignored. Non-TCP traffic (ARP, ICMPv6) is ignored.

## Reassembly

Each direction is reassembled by TCP sequence number relative to its initial sequence number. Exact
retransmissions and the already-seen part of overlapping segments are ignored (counted in
`retransmitted_pkts`); out-of-order segments are held until the gap is filled. TLS records are then cut from
the reassembled stream, so records that span several segments (or one segment holding several records) are
handled. A trailing partial record is not counted as a record.

## Handshake phase vs application phase

- **Handshake phase:** from the SYN to the end of the client's **first ApplicationData record** (TLS record
  type 23). In TLS 1.3 that record is the client Finished (the client's ChangeCipherSpec, type 20, is skipped).
- **Application phase:** everything after that point.
- Client bytes are split exactly at the end of that record (a segment that straddles the boundary counts as a
  packet in both phases, so `hs_*_pkts + app_*_pkts` can exceed the number of segments by the number of
  straddling segments; `total_pkts` counts each segment once).
- Server bytes are split by capture order: server segments captured **before** the segment that completes the
  client's Finished are handshake, later ones are application. The server's Finished is always sent before the
  client can answer, so this puts the whole server flight in the handshake phase.
- `hs_duration` = time from the SYN to the packet that completes the client's first ApplicationData record.

### Limits of this heuristic

- It assumes the first client type-23 record is the Finished. A client that sent 0-RTT early data, or any
  application data before Finished, would break this. The lab client does not.
- It assumes the server sends no application data before it has seen the client Finished (no 0.5-RTT data) and
  no post-handshake messages before then. The lab disables session tickets (`-no_ticket -num_tickets 0`);
  with tickets enabled, the two NewSessionTicket records would land in the application phase of each connection.
- The server's close alert (and the client's) falls in the application phase: a flood connection that sends no
  data shows exactly one 24-byte packet each way. 24 bytes is a record header (5) plus a 19-byte payload
  (2-byte alert, 1-byte inner type, 16-byte AEAD tag), consistent with an encrypted close_notify. This is
  inferred from size and position; it is not proven, because nothing is decrypted.
- If no client type-23 record exists, `handshake_complete = False`, everything is counted as handshake, and the
  application features are empty.
- A connection whose capture starts mid-way (no SYN) is ignored, not guessed.

## Definitions

- **Bytes** are TCP payload bytes (no IP/TCP headers). **Packets** are non-duplicate TCP segments that carry
  payload as seen at the capture point.
- **NIC offloads and packet features.** On virtual interfaces the kernel merges received segments (GRO) and
  defers segmentation of sent data (GSO/TSO), so a capture shows "packets" of up to ~64 KB. That is a capture
  artefact, not wire behaviour: byte counts are unaffected, but packet counts and packet-length statistics
  would depend on the capture setup. The first mini-run showed it (largest TCP payload 65,160 bytes).
  The lab therefore runs `ethtool -K eth0 gro off gso off tso off lro off` in the server namespace (from the
  capture container, which shares it) and in the client container (`lab/offload_off.sh`), and VERIFIES the
  result with `ethtool -k`. After the fix the largest payload is 1,448 bytes (MSS with TCP timestamps) and a
  15,976-byte server flight is exactly 12 packets. Every manifest row records `max_tcp_payload` and
  `capture_offload_ok`: true only if both sides read back "off" AND no packet carried more than 1,460 payload
  bytes. If a pcap shows `capture_offload_ok = false`, do NOT use its packet-based features (`*_pkts`,
  `app_pkt_len_*`, `app_iat_*`, `app_c2s_size_*`, `app_s2c_size_*`, `app_tiny_client_pkts`); byte features remain
  valid. LRO reads "off [fixed]" on these interfaces (cannot be enabled).
- `app_pkt_len_*`: over all application-phase payload packets, both directions. `app_iat_*`: gaps between
  consecutive application-phase payload packets, both directions pooled (capture order). `std` is the
  population standard deviation (ddof = 0). Statistics over an empty set are NaN; `app_duration` is 0.0 when
  there are fewer than two application packets.
- `flow_*` (whole-connection, CICFlowMeter-like; `LAB_FLOW_FEATURES`): computed over ALL TCP packets of the
  connection, handshake and application phase together, including SYN, pure ACKs, FINs and retransmissions.
  `flow_c2s_pkts` / `flow_s2c_pkts` count every packet per direction; `flow_c2s_bytes` / `flow_s2c_bytes` sum their
  payload bytes (so they include retransmitted bytes, unlike `total_bytes`); `flow_pkt_len_*` are over every
  packet's payload length (0 for pure ACKs); `flow_iat_*` are the gaps between consecutive packets of the
  connection in capture order. This is the view an off-the-shelf flow-feature detector gets: it does not
  separate handshake from application traffic.
- `app_tiny_client_pkts`: client application packets with 1-60 payload bytes.
- `app_c2s_size_1..10` / `app_s2c_size_1..10`: sizes of the first ten application-phase packets per direction
  (NaN when fewer).
- `sh_group_id`, `sh_cipher_suite`: read from the cleartext ServerHello (key_share extension). Group ids
  (x25519 0x001d, MLKEM768 0x0201, X25519MLKEM768 0x11ec) are marked VERIFY in `pqdl.pcap`.
- `flow_duration`: first to last packet of the connection, including FIN/ACK packets.

## Validation (scripts/pcaps_to_flows.py)

1. connections found vs `n_sessions` in the manifest;
2. handshake_flood handshake bytes vs OpenSSL's own client read/written counts from `lab/smoke_test.sh`,
   obtained by running it through docker at validation time;
3. ServerHello group id vs the manifest KEM for every connection;
4. benign_web application-phase features carry no handshake bytes (same handshake bytes as the flood pcap,
   `hs + app == total`, and `app_s2c_bytes` within 1% + 100 B above the bytes the client logged).

The thresholds in check 4 were fixed before the run and are not adjusted to make a check pass.
