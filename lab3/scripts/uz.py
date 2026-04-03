import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple


HEADER_FORMAT = "!BBIH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
PKT_LEGIT = 0x01
PKT_DUMMY = 0x02
PKT_END = 0x03


def parse_args():
    parser = argparse.ArgumentParser(description="Protection device for the covert-channel lab")
    parser.add_argument("--listen-ip", default="0.0.0.0", help="Local IP to listen on")
    parser.add_argument("--listen-port", type=int, default=9000, help="Local UDP port")
    parser.add_argument("--forward-ip", required=True, help="Destination IP")
    parser.add_argument("--forward-port", type=int, default=9001, help="Destination UDP port")
    parser.add_argument(
        "--mode",
        choices=("passthrough", "jitter", "normalize"),
        default="passthrough",
        help="Protection mode",
    )
    parser.add_argument(
        "--jitter-max-delay",
        type=float,
        default=0.35,
        help="Maximum random delay in seconds for jitter mode",
    )
    parser.add_argument(
        "--normalize-quantum",
        type=float,
        default=0.1,
        help="Packet release period in seconds for normalize mode",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=1.0,
        help="Time in seconds to wait after end marker before stopping",
    )
    parser.add_argument("--stats-file", default="uz_stats.json", help="Path to JSON file with proxy stats")
    return parser.parse_args()


def packet_type_of(data: bytes) -> str:
    if len(data) < HEADER_SIZE:
        return "unknown"
    packet_type, _, _, _ = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
    if packet_type == PKT_LEGIT:
        return "legit"
    if packet_type == PKT_DUMMY:
        return "dummy"
    if packet_type == PKT_END:
        return "end"
    return "unknown"


def filler_packet() -> bytes:
    return struct.pack(HEADER_FORMAT, PKT_DUMMY, 0, 0, 0)


def record(stats: Dict[str, object], prefix: str, packet_kind: str, size: int) -> None:
    stats[f"{prefix}_packets"] += 1
    stats[f"{prefix}_bytes"] += size
    key = f"{prefix}_{packet_kind}_packets"
    if key in stats:
        stats[key] += 1
    bytes_key = f"{prefix}_{packet_kind}_bytes"
    if bytes_key in stats:
        stats[bytes_key] += size


def forward_packet(sock: socket.socket, dst: Tuple[str, int], packet: bytes, stats: Dict[str, object], packet_kind: str) -> None:
    sock.sendto(packet, dst)
    stats["last_forward_ts"] = time.time()
    record(stats, "egress", packet_kind, len(packet))
    print(f"[UZ] forwarded {packet_kind} packet, {len(packet)} bytes")


def save_stats(args, stats: Dict[str, object], started_at: float, finished_at: float) -> None:
    duration = max(finished_at - started_at, 1e-9)
    stats["mode"] = args.mode
    stats["started_at"] = started_at
    stats["finished_at"] = finished_at
    stats["duration_seconds"] = duration
    stats["ingress_rate_Bps"] = stats["ingress_bytes"] / duration
    stats["egress_rate_Bps"] = stats["egress_bytes"] / duration
    stats["legit_goodput_Bps"] = stats["egress_legit_bytes"] / duration
    root, ext = os.path.splitext(args.stats_file)
    stats_path = f"{root}_{args.mode}{ext or '.json'}"
    with open(stats_path, "w", encoding="utf-8") as stats_file:
        json.dump(stats, stats_file, indent=2)
    print(f"[UZ] stats saved to {stats_path}")


def passthrough_or_jitter(args, sock: socket.socket, dst: Tuple[str, int], stats: Dict[str, object]) -> None:
    end_received_at: Optional[float] = None
    while True:
        try:
            data, src = sock.recvfrom(65535)
        except socket.timeout:
            if end_received_at is not None and (time.time() - end_received_at) >= args.idle_timeout:
                return
            continue

        packet_kind = packet_type_of(data)
        stats["last_recv_ts"] = time.time()
        record(stats, "ingress", packet_kind, len(data))
        print(f"[UZ] received {packet_kind} packet from {src[0]}:{src[1]}, {len(data)} bytes")

        if args.mode == "jitter":
            delay = random.uniform(0.0, max(0.0, args.jitter_max_delay))
            time.sleep(delay)
            stats["total_added_delay_seconds"] += delay

        forward_packet(sock, dst, data, stats, packet_kind)

        if packet_kind == "end":
            end_received_at = time.time()


def normalize(args, sock: socket.socket, dst: Tuple[str, int], stats: Dict[str, object]) -> None:
    queue: Deque[Tuple[bytes, str]] = deque()
    end_received = False
    last_real_ingress = time.time()
    next_release = time.monotonic() + max(args.normalize_quantum, 0.001)

    while True:
        now = time.monotonic()
        timeout = max(0.0, min(0.05, next_release - now))
        sock.settimeout(timeout)

        try:
            data, src = sock.recvfrom(65535)
            packet_kind = packet_type_of(data)
            stats["last_recv_ts"] = time.time()
            record(stats, "ingress", packet_kind, len(data))
            print(f"[UZ] received {packet_kind} packet from {src[0]}:{src[1]}, {len(data)} bytes")
            if packet_kind == "end":
                end_received = True
                last_real_ingress = time.time()
            else:
                queue.append((data, packet_kind))
                last_real_ingress = time.time()
        except (socket.timeout, BlockingIOError):
            pass

        now = time.monotonic()
        if now < next_release:
            continue

        if queue:
            packet, packet_kind = queue.popleft()
            forward_packet(sock, dst, packet, stats, packet_kind)
        else:
            forward_packet(sock, dst, filler_packet(), stats, "filler")

        next_release += max(args.normalize_quantum, 0.001)

        if end_received and not queue and (time.time() - last_real_ingress) >= args.idle_timeout:
            end_packet = struct.pack(HEADER_FORMAT, PKT_END, 0, 0, 0)
            forward_packet(sock, dst, end_packet, stats, "end")
            return


def main():
    args = parse_args()
    if args.jitter_max_delay < 0:
        raise SystemExit("[UZ] jitter-max-delay must be non-negative")
    if args.normalize_quantum <= 0:
        raise SystemExit("[UZ] normalize-quantum must be positive")
    if args.idle_timeout < 0:
        raise SystemExit("[UZ] idle-timeout must be non-negative")

    random.seed(time.time_ns())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_ip, args.listen_port))
    sock.settimeout(0.2)
    dst = (args.forward_ip, args.forward_port)

    stats: Dict[str, object] = {
        "ingress_packets": 0,
        "ingress_bytes": 0,
        "ingress_legit_packets": 0,
        "ingress_dummy_packets": 0,
        "ingress_end_packets": 0,
        "ingress_unknown_packets": 0,
        "egress_packets": 0,
        "egress_bytes": 0,
        "egress_legit_packets": 0,
        "egress_dummy_packets": 0,
        "egress_filler_packets": 0,
        "egress_end_packets": 0,
        "egress_unknown_packets": 0,
        "egress_legit_bytes": 0,
        "total_added_delay_seconds": 0.0,
        "last_recv_ts": None,
        "last_forward_ts": None,
    }

    started_at = time.time()
    print(
        f"[UZ] mode={args.mode}, listening on {args.listen_ip}:{args.listen_port}, "
        f"forwarding to {args.forward_ip}:{args.forward_port}"
    )

    try:
        if args.mode in ("passthrough", "jitter"):
            passthrough_or_jitter(args, sock, dst, stats)
        else:
            normalize(args, sock, dst, stats)
    finally:
        finished_at = time.time()
        save_stats(args, stats, started_at, finished_at)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[UZ] stopped")
        sys.exit(0)
