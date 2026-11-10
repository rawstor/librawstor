#!/bin/bash
# Stage 0 benchmark of docs/security.md: plain TCP vs kTLS vs userspace TLS on
# loopback, io_uring send/recv. Needs: gcc, liburing-dev, libssl-dev, openssl,
# python3, and for kTLS the `tls` kernel module (sudo modprobe tls).
#
#   ./run.sh                      # full matrix into ./results/
#   SECS=5 REPS=5 CPU_S=4 CPU_C=5 OUT=/tmp/r ./run.sh
#
# Server and client are pinned to different cores (CPU_S, CPU_C). Loopback
# measures CPU cost and latency added by TLS, not NIC or network behaviour.
set -eu
cd "$(dirname "$0")"

OUT=${OUT:-results}
CPU_S=${CPU_S:-2}
CPU_C=${CPU_C:-3}
SECS=${SECS:-3}
REPS=${REPS:-3}
HS_CONNS=${HS_CONNS:-2000}
MODES=${MODES:-"plain ktls ubio ufd"}
mkdir -p "$OUT/certs"
RAW="$OUT/raw.txt"
: > "$RAW"

gcc -O2 -Wall -o "$OUT/bench" bench.c -luring -lssl -lcrypto

C="$OUT/certs"
if [ ! -f "$C/server.pem" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$C/ca.key" 2>/dev/null
    openssl req -x509 -new -key "$C/ca.key" -sha256 -days 30 -subj "/CN=bench-ca" \
        -out "$C/ca.pem" 2>/dev/null
    for r in server client; do
        openssl ecparam -name prime256v1 -genkey -noout -out "$C/$r.key" 2>/dev/null
        if [ "$r" = server ]; then
            san="URI:spiffe://bench.example/ost/1"
        else
            san="URI:spiffe://bench.example/tenant/t/client/c"
        fi
        openssl req -new -key "$C/$r.key" -subj "/CN=$r" -out "$C/$r.csr" 2>/dev/null
        printf "subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\n" \
            "$san" > "$C/$r.ext"
        openssl x509 -req -in "$C/$r.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" \
            -CAcreateserial -days 30 -sha256 -extfile "$C/$r.ext" -out "$C/$r.pem" 2>/dev/null
    done
fi

PORT=7800
pair() { # tag, common args...
    local tag=$1
    shift
    PORT=$((PORT + 1))
    {
        echo "RUN $tag"
        "$OUT/bench" server --certs "$C" --port $PORT --cpu "$CPU_S" "$@" 2>&1 &
        local spid=$!
        sleep 0.3
        "$OUT/bench" client --certs "$C" --port $PORT --cpu "$CPU_C" "$@" 2>&1 || true
        wait $spid || true
    } >> "$RAW"
}

echo "kernel $(uname -r)  openssl $(openssl version | cut -d' ' -f2)  cpus $CPU_S/$CPU_C" >> "$RAW"

echo "== streams (1 MiB)"
for rep in $(seq "$REPS"); do
    for cipher in TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256; do
        for m in $MODES; do
            for w in up down; do
                [ "$m" = plain ] && [ "$cipher" = TLS_AES_128_GCM_SHA256 ] && continue
                pair "stream cipher=$cipher rep=$rep" --mode "$m" --work "$w" \
                    --size 1048576 --secs "$SECS" --cipher "$cipher"
            done
        done
    done
done

echo "== request/response (4 KiB)"
for rep in $(seq "$REPS"); do
    for qd in 1 32; do
        for prof in "w 4144 16" "r 48 4112"; do
            set -- $prof
            for m in $MODES; do
                pair "rr profile=$1 rep=$rep" --mode "$m" --work rr --req "$2" \
                    --resp "$3" --qd "$qd" --secs "$SECS"
            done
        done
    done
done

echo "== handshakes"
for rep in $(seq "$REPS"); do
    for hs in tcp full resume; do
        pair "hs rep=$rep" --mode ufd --work hs --hs "$hs" --conns "$HS_CONNS"
    done
done

echo "== io_uring feature probes"
for m in plain ktls; do
    pair "probe" --mode "$m" --work probe --conns 9
done

python3 -I summarize.py "$RAW" | tee "$OUT/summary.md"
