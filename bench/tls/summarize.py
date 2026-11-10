"""Turn raw.txt of run.sh into markdown tables (medians over repetitions)."""
import re
import statistics
import sys
from collections import defaultdict

MODES = ["plain", "ktls", "ubio", "ufd"]
NAMES = {
    "plain": "plain TCP",
    "ktls": "kTLS",
    "ubio": "userspace TLS (memory BIO)",
    "ufd": "userspace TLS (SSL on fd)",
}


def kv(line):
    out = {}
    if " result=" in line:
        line, res = line.split(" result=", 1)
        out["result"] = res
    for part in line.split()[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def med(xs):
    return statistics.median(xs) if xs else float("nan")


def main(path):
    header = ""
    runs = []  # (tag, client, server, probes)
    cur = None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("kernel "):
                header = line
            elif line.startswith("RUN "):
                cur = {"tag": line[4:], "client": None, "server": None, "probes": []}
                runs.append(cur)
            elif cur is not None and line.startswith("CLIENT "):
                cur["client"] = kv(line)
            elif cur is not None and line.startswith("SERVER "):
                cur["server"] = kv(line)
            elif cur is not None and line.startswith("PROBE "):
                cur["probes"].append(kv(line))
            elif line.startswith("KTLS_NOT_ACTIVE") or line.startswith("FATAL"):
                if cur is not None:
                    cur.setdefault("errors", []).append(line)

    print("# TLS cost on the io_uring data path (loopback)\n")
    print(f"`{header}`\n")

    # ---- streams
    st = defaultdict(list)
    for r in runs:
        if not r["tag"].startswith("stream") or not r["client"] or not r["server"]:
            continue
        c, s = r["client"], r["server"]
        cipher = re.search(r"cipher=(\S+)", r["tag"]).group(1)
        gbs = float(c["bytes"]) / float(c["secs"]) / 1e9
        cpu_c = (float(c["cpu_user"]) + float(c["cpu_sys"])) / (float(c["bytes"]) / 1e9)
        cpu_s = (float(s["cpu_user"]) + float(s["cpu_sys"])) / max(float(s["bytes"]) / 1e9, 1e-9)
        st[(cipher, c["work"], c["mode"])].append((gbs, cpu_c + cpu_s))
    if st:
        print("## Streams, 1 MiB messages, one connection\n")
        print("Throughput and CPU seconds per GB (client + server, user + kernel).\n")
        print("| cipher | direction | transport | GB/s | CPU s/GB | vs plain (GB/s) |")
        print("|---|---|---|---|---|---|")
        for cipher in ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]:
            for work in ["up", "down"]:
                base = med([x[0] for x in st.get(("TLS_AES_256_GCM_SHA384", work, "plain"), [])])
                for m in MODES:
                    v = st.get((cipher, work, m))
                    if not v:
                        continue
                    g, c = med([x[0] for x in v]), med([x[1] for x in v])
                    print(
                        f"| {cipher.replace('TLS_', '')} | {work} | {NAMES[m]} | "
                        f"{g:.2f} | {c:.2f} | {g / base * 100:.0f}% |"
                    )
        print()

    # ---- rr
    rr = defaultdict(list)
    for r in runs:
        if not r["tag"].startswith("rr") or not r["client"] or not r["server"]:
            continue
        c, s = r["client"], r["server"]
        prof = re.search(r"profile=(\S+)", r["tag"]).group(1)
        ops = float(c["ops"])
        cpu = (
            float(c["cpu_user"]) + float(c["cpu_sys"]) + float(s["cpu_user"]) + float(s["cpu_sys"])
        ) / ops * 1e6
        rr[(prof, int(c["qd"]), c["mode"])].append(
            (float(c["iops"]), float(c["p50_us"]), float(c["p99_us"]), float(c["p999_us"]), cpu)
        )
    if rr:
        print("## Request/response, 4 KiB payload\n")
        print(
            "`w` = 4 KiB request + 16 B response (a WRITE); `r` = 48 B request + "
            "4 KiB response (a READ). One connection. CPU is client + server per operation.\n"
        )
        print("| op | queue depth | transport | IOPS | p50 µs | p99 µs | p99.9 µs | CPU µs/op |")
        print("|---|---|---|---|---|---|---|---|")
        for prof in ["w", "r"]:
            for qd in [1, 32]:
                for m in MODES:
                    v = rr.get((prof, qd, m))
                    if not v:
                        continue
                    cols = [med([x[i] for x in v]) for i in range(5)]
                    print(
                        f"| {prof} | {qd} | {NAMES[m]} | {cols[0]:,.0f} | {cols[1]:.1f} | "
                        f"{cols[2]:.1f} | {cols[3]:.1f} | {cols[4]:.1f} |"
                    )
        print()

    # ---- handshakes
    hs = defaultdict(list)
    for r in runs:
        if not r["tag"].startswith("hs") or not r["client"] or not r["server"]:
            continue
        c, s = r["client"], r["server"]
        n = float(c["conns"])
        cpu = (
            float(c["cpu_user"]) + float(c["cpu_sys"]) + float(s["cpu_user"]) + float(s["cpu_sys"])
        ) / n * 1e3
        hs[c["hs"]].append((float(c["hs_per_s"]), cpu, int(c["reused"])))
    if hs:
        print("## Connection setup (mTLS, ECDSA P-256, X25519)\n")
        print("| setup | connections/s | CPU ms/connection (both sides) |")
        print("|---|---|---|")
        labels = {"tcp": "TCP connect only", "full": "full TLS 1.3 handshake", "resume": "resumed (session ticket)"}
        for k in ["tcp", "full", "resume"]:
            v = hs.get(k)
            if v:
                print(
                    f"| {labels[k]} | {med([x[0] for x in v]):,.0f} | {med([x[1] for x in v]):.3f} |"
                )
        print()

    # ---- probes
    pr = defaultdict(dict)
    for r in runs:
        for p in r["probes"]:
            pr[p["op"]][p["mode"]] = p["result"]
        for e in r.get("errors", []):
            pr["(error)"][r["tag"]] = e
    if pr:
        print("## io_uring features on a kTLS socket\n")
        print("256 KiB of a known pattern echoed through the server; the result is `ok` only if every byte matches.\n")
        print("| operation | plain | kTLS |")
        print("|---|---|---|")
        order = ["send", "sendmsg", "send_zc", "send_zc_fixed", "write_fixed",
                 "recv_bufsel", "recv_multishot", "read_fixed", "sendfile"]
        for op in order:
            if op in pr:
                print(f"| `{op}` | {pr[op].get('plain', '-')} | {pr[op].get('ktls', '-')} |")
        print()


if __name__ == "__main__":
    main(sys.argv[1])
