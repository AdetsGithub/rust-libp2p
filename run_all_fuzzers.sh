#!/usr/bin/env bash
#
# Run every fuzz target in rust-libp2p.
#
# Targets:
#   * core/fuzz/  — 30 cargo-fuzz targets (parsers, behaviours, transports)
#   * fuzz/       —  1 cargo-fuzz target  (gossipsub_structured)
#
# Each target is built and then run until either `RUNS` libFuzzer iterations
# (default: smoke-test mode) or, when `MAX_TOTAL_TIME` is set, a per-target
# time budget via libFuzzer's `-max_total_time` (clean exit, no `timeout`
# kill). Per-target logs land in `LOG_DIR`; a pass/fail summary is printed at
# the end and the script exits non-zero if any target failed.
#
# Usage:
#   ./run_all_fuzzers.sh                         # 20 iterations per target (default)
#   RUNS=100 ./run_all_fuzzers.sh                # override iteration count
#   MAX_TOTAL_TIME=120 ./run_all_fuzzers.sh      # 2 minutes per target (real run)
#   TIMEOUT_SECS=600 ./run_all_fuzzers.sh        # safety-net timeout (per target)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_FUZZ_DIR="$SCRIPT_DIR/core/fuzz"
ROOT_FUZZ_DIR="$SCRIPT_DIR/fuzz"

RUNS="${RUNS:-20}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-}"
TIMEOUT_SECS="${TIMEOUT_SECS:-900}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/fuzz_run_logs}"
SUMMARY="$LOG_DIR/summary.txt"

if [ -n "$MAX_TOTAL_TIME" ]; then
    RUN_DESC="$MAX_TOTAL_TIME sec/target"
else
    RUN_DESC="$RUNS runs/target"
fi

mkdir -p "$LOG_DIR"

# libFuzzer symbolization stalls this host to ~1 exec/s; disable it.
export ASAN_OPTIONS="symbolize=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"

# ---------------------------------------------------------------------------
# Target metadata
# ---------------------------------------------------------------------------

# Ordered list of core/fuzz targets (matches core/fuzz/Cargo.toml [[bin]]).
CORE_TARGETS=(
    multiaddr_roundtrip
    multiaddr_binary
    multiaddr_text
    multiaddr_protocol_from_bytes
    multiaddr_structured
    peer_id_from_bytes
    unsigned_varint_roundtrip
    mplex_frame_codec
    mplex_multiplexed_io
    multistream_select_negotiation
    yamux_frame_header
    gossipsub_behaviour
    gossipsub_handler
    gossipsub_strict_signed
    kademlia_behaviour
    kademlia_handler
    identify_behaviour
    identify_handler
    relay_behaviour
    dcutr_behaviour
    dcutr_outbound
    request_response_behaviour
    swarm_orchestrator
    swarm_circuit
    noise_handshake
    tls_handshake
    quic_handshake
    autonat_behaviour
    autonatv2_client
    autonatv2_server
)

# Root-level fuzz crate targets.
ROOT_TARGETS=(
    gossipsub_structured
)

# Extra libFuzzer flags (everything after `--`) for a core/fuzz target.
# Dict paths are relative to core/fuzz/. Mirrors README-fuzzing.md's run matrix.
core_args() {
    case "$1" in
        multiaddr_roundtrip)          echo "-dict=dicts/multiaddr.dict" ;;
        multiaddr_binary)             echo "-dict=dicts/multiaddr.dict" ;;
        multiaddr_text)               echo "-dict=dicts/multiaddr.dict" ;;
        multiaddr_protocol_from_bytes) echo "-dict=dicts/multiaddr.dict" ;;
        multiaddr_structured)         echo "-dict=dicts/multiaddr.dict" ;;
        peer_id_from_bytes)           echo "-dict=dicts/peer_id.dict" ;;
        unsigned_varint_roundtrip)    echo "-dict=dicts/unsigned_varint.dict" ;;
        mplex_frame_codec)            echo "-dict=dicts/mplex.dict" ;;
        mplex_multiplexed_io)         echo "-dict=dicts/mplex.dict" ;;
        multistream_select_negotiation) echo "-dict=dicts/multistream.dict" ;;
        yamux_frame_header)           echo "-dict=dicts/yamux.dict -max_len=65536" ;;
        gossipsub_behaviour)          echo "-dict=dicts/gossipsub.dict -max_len=4096 -len_control=0" ;;
        gossipsub_handler)            echo "-dict=dicts/gossipsub.dict -max_len=4096 -len_control=0" ;;
        gossipsub_strict_signed)      echo "-dict=dicts/gossipsub.dict -max_len=4096 -len_control=0" ;;
        kademlia_behaviour)           echo "-dict=dicts/kademlia.dict -max_len=4096 -len_control=0" ;;
        kademlia_handler)             echo "-dict=dicts/kademlia.dict -max_len=4096 -len_control=0" ;;
        identify_behaviour)           echo "-dict=dicts/identify.dict -max_len=4096 -len_control=0" ;;
        identify_handler)             echo "-dict=dicts/identify.dict -max_len=4096 -len_control=0" ;;
        relay_behaviour)              echo "-dict=dicts/relay_behaviour.dict -max_len=4096 -len_control=0" ;;
        dcutr_behaviour)              echo "-dict=dicts/dcutr_behaviour.dict -max_len=4096 -len_control=0" ;;
        dcutr_outbound)               echo "-dict=dicts/dcutr_behaviour.dict -max_len=4096 -len_control=0" ;;
        request_response_behaviour)   echo "-max_len=4096 -len_control=0" ;;
        swarm_orchestrator)           echo "-dict=dicts/swarm.dict -max_len=512 -len_control=0" ;;
        swarm_circuit)                echo "-dict=dicts/swarm_circuit.dict -max_len=512 -len_control=0" ;;
        noise_handshake)              echo "-dict=dicts/noise.dict -max_len=4096" ;;
        tls_handshake)                echo "-max_len=4096" ;;
        quic_handshake)               echo "-max_len=4096 -len_control=0" ;;
        autonat_behaviour)            echo "-max_len=4096 -len_control=0" ;;
        autonatv2_client)             echo "-max_len=4096 -len_control=0" ;;
        autonatv2_server)             echo "-max_len=4096 -len_control=0" ;;
        *)                            echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
FAILED_TARGETS=()

# Run a single fuzz target from `dir`. Returns 0 on success, 1 on failure.
run_one() {
    local dir="$1"
    local target="$2"
    local extra="$3"
    local log="$LOG_DIR/$target.log"

    # Stop condition: `-max_total_time` (clean libFuzzer exit) when a time
    # budget is set, otherwise `-runs`. `timeout` remains a safety net only.
    local run_flag ttl
    if [ -n "$MAX_TOTAL_TIME" ]; then
        run_flag="-max_total_time=$MAX_TOTAL_TIME"
        ttl=$((MAX_TOTAL_TIME + 60)) # build/startup buffer
    else
        run_flag="-runs=$RUNS"
        ttl="$TIMEOUT_SECS"
    fi

    : > "$log"
    printf '  %-34s' "$target"
    if (cd "$dir" && timeout "$ttl" cargo +nightly fuzz run "$target" -- \
            $run_flag -print_funcs=0 $extra) >> "$log" 2>&1; then
        echo "ok"
        PASS=$((PASS + 1))
        return 0
    fi
    echo "FAIL  (log: $log)"
    FAIL=$((FAIL + 1))
    FAILED_TARGETS+=("$target")
    return 1
}

# ---------------------------------------------------------------------------
# Build (surfaces compile errors up front) then run
# ---------------------------------------------------------------------------

echo "=== Building core/fuzz targets ==="
if ! (cd "$CORE_FUZZ_DIR" && cargo +nightly fuzz build) > "$LOG_DIR/build_core.log" 2>&1; then
    echo "core/fuzz build FAILED — see $LOG_DIR/build_core.log"
    exit 1
fi
echo "core/fuzz build ok"

echo "=== Building fuzz/ targets ==="
if ! (cd "$ROOT_FUZZ_DIR" && cargo +nightly fuzz build gossipsub_structured) > "$LOG_DIR/build_root.log" 2>&1; then
    echo "fuzz/ build FAILED — see $LOG_DIR/build_root.log"
    exit 1
fi
echo "fuzz/ build ok"

echo
echo "=== Running core/fuzz targets ($RUN_DESC) ==="
for t in "${CORE_TARGETS[@]}"; do
    run_one "$CORE_FUZZ_DIR" "$t" "$(core_args "$t")"
done

echo
echo "=== Running fuzz/ targets ($RUN_DESC) ==="
for t in "${ROOT_TARGETS[@]}"; do
    run_one "$ROOT_FUZZ_DIR" "$t" "-max_len=4096"
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

{
    echo "rust-libp2p fuzz smoke-test summary"
    echo "==================================="
    echo "run id:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "duration:     $RUN_DESC"
    echo "passed:       $PASS"
    echo "failed:       $FAIL"
    if [ "$FAIL" -gt 0 ]; then
        echo "failed targets:"
        printf '  - %s\n' "${FAILED_TARGETS[@]}"
    fi
} | tee "$SUMMARY"

echo
if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL — $FAIL target(s) failed."
    exit 1
fi
echo "RESULT: PASS — all $PASS fuzz targets built and ran successfully."
