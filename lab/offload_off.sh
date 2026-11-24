#!/usr/bin/env bash
# Turn off GRO/GSO/TSO/LRO on one interface of THIS network namespace, then VERIFY the result.
# On virtual interfaces these offloads merge or defer segments, so a capture shows "packets" of up to
# ~64 KB instead of wire-sized segments (<= MSS), which would distort packet counts and packet-length
# features. Usage: offload_off.sh ROLE [IFACE]   (needs CAP_NET_ADMIN)
# Prints one line:  OFFLOAD <role> <iface>: ok | FAILED (...)   followed by the four feature states.
# Exit status 0 if all four are off, 1 otherwise. A failure is never hidden: callers record it.
set -u
role="${1:?role (server|client)}"; ifc="${2:-eth0}"
features=(generic-receive-offload generic-segmentation-offload tcp-segmentation-offload large-receive-offload)

if ! command -v ethtool >/dev/null 2>&1; then echo "OFFLOAD $role $ifc: FAILED (ethtool not installed)"; exit 1; fi
ethtool -K "$ifc" gro off gso off tso off lro off >/dev/null 2>&1   # may partly fail; verified below
state="$(ethtool -k "$ifc" 2>&1)"
bad=""; summary=""
for f in "${features[@]}"; do
  line="$(printf '%s\n' "$state" | grep "^$f:" | head -1)"
  summary+="${line:-$f: (not reported)}; "
  case "$line" in *": off"*) ;; *) bad+=" $f" ;; esac
done
if [ -z "$bad" ]; then echo "OFFLOAD $role $ifc: ok"; else echo "OFFLOAD $role $ifc: FAILED (still on or unreadable:$bad)"; fi
echo "OFFLOAD-STATE $role $ifc: $summary"
[ -z "$bad" ]
