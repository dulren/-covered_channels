import argparse
import json
import os
import random
import socket
import struct
import sys
import time
from typing import List


HEADER_FORMAT = "!BBIH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
PKT_LEGIT = 0x01
PKT_DUMMY = 0x02
PKT_END = 0x03
FLAG_LAST = 0x01

THRESHOLD = 5
LOW_COUNT = 1
HIGH_COUNT = 10
MIN_PACKET_LEN = 48
MAX_PACKET_LEN = 96
ANCHOR_OFFSET_RATIO = 0.20
WINDOW_START_RATIO = 0.30
WINDOW_END_RATIO = 0.70


def parse_args():
    parser = argparse.ArgumentParser(
        description="sender: legitimate traffic plus covert channel based on packet intensity"
    )
    parser.add_argument("--main-file", default="mainfile.txt", help="Legitimate input file")
    parser.add_argument("--covert-file", default="coveredfile.txt", help="Hidden input file")
    parser.add_argument("--dst-ip", required=True, help="Proxy IP address")
    parser.add_argument("--dst-port", type=int, default=9000, help="Proxy UDP port")
    parser.add_argument("--interval", type=float, default=1.0, help="Slot duration in seconds")
    parser.add_argument("--block-size", type=int, default=32, help="Legitimate payload block size")
    parser.add_argument("--stats-file", default="p1_stats.json", help="Path to JSON file with sender stats")
    return parser.parse_args()


def load_chunks(path: str, block_size: int) -> List[bytes]:
    data = open(path, "rb").read()
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def covert_bits(path: str) -> List[int]:
    data = open(path, "rb").read()
    length_prefix = len(data).to_bytes(4, "big")
    payload = length_prefix + data
    bits: List[int] = []
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def build_packet(packet_type: int, seq: int, payload: bytes, is_last: bool, min_len: int, max_len: int) -> bytes:
    flags = FLAG_LAST if is_last else 0
    header = struct.pack(HEADER_FORMAT, packet_type, flags, seq, len(payload))
    min_total = max(min_len, HEADER_SIZE + len(payload))
    max_total = max(max_len, min_total)
    total_len = random.randint(min_total, max_total)
    pad_len = total_len - HEADER_SIZE - len(payload)
    return header + payload + os.urandom(pad_len)


def build_dummy_packet(seq: int, min_len: int, max_len: int) -> bytes:
    payload = os.urandom(random.randint(0, max(0, min_len - HEADER_SIZE)))
    return build_packet(PKT_DUMMY, seq, payload, False, min_len, max_len)


def build_end_packet() -> bytes:
    return struct.pack(HEADER_FORMAT, PKT_END, 0, 0, 0)


def slot_schedule(slot_base: float, interval: float, packet_count: int) -> List[float]:
    schedule = [slot_base + interval * ANCHOR_OFFSET_RATIO]
    if packet_count == 1:
        return schedule

    offsets = sorted(
        random.uniform(WINDOW_START_RATIO, WINDOW_END_RATIO) * interval
        for _ in range(packet_count - 1)
    )
    schedule.extend(slot_base + offset for offset in offsets)
    return schedule


def main():
    args = parse_args()
    random.seed(time.time_ns())
    if args.interval <= 0:
        raise SystemExit("[P1] interval must be positive")
    if args.block_size <= 0:
        raise SystemExit("[P1] block-size must be positive")

    legit_chunks = load_chunks(args.main_file, args.block_size)
    legit_bytes = sum(len(chunk) for chunk in legit_chunks)
    hidden_bits = covert_bits(args.covert_file)
    hidden_bytes = max(0, (len(hidden_bits) - 32) // 8)
    print(f"[P1] legit chunks: {len(legit_chunks)}, covert bits: {len(hidden_bits)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dst = (args.dst_ip, args.dst_port)
    slot_index = 0
    legit_index = 0
    legit_seq = 1
    dummy_seq = 1
    base_time = time.monotonic() + max(0.5, args.interval)
    started_at = time.time()

    while legit_index < len(legit_chunks) or slot_index < len(hidden_bits):
        slot_started = base_time + slot_index * args.interval
        current_bit = hidden_bits[slot_index] if slot_index < len(hidden_bits) else 0
        target_count = HIGH_COUNT if current_bit == 1 else LOW_COUNT

        packets: List[bytes] = []
        if legit_index < len(legit_chunks):
            chunk = legit_chunks[legit_index]
            is_last = legit_index == len(legit_chunks) - 1
            packets.append(
                build_packet(
                    PKT_LEGIT,
                    legit_seq,
                    chunk,
                    is_last,
                    MIN_PACKET_LEN,
                    MAX_PACKET_LEN,
                )
            )
            legit_index += 1
            legit_seq += 1

        while len(packets) < target_count:
            packets.append(build_dummy_packet(dummy_seq, MIN_PACKET_LEN, MAX_PACKET_LEN))
            dummy_seq += 1

        send_times = slot_schedule(slot_started, args.interval, len(packets))
        for send_at, packet in zip(send_times, packets):
            delay = send_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            sock.sendto(packet, dst)

        slot_end = slot_started + args.interval
        delay = slot_end - time.monotonic()
        if delay > 0:
            time.sleep(delay)

        print(
            f"[P1] slot={slot_index} bit={current_bit} target_packets={target_count} "
            f"legit_sent={1 if packets and packets[0][0] == PKT_LEGIT else 0}"
        )
        slot_index += 1

    end_packet = build_end_packet()
    for _ in range(3):
        sock.sendto(end_packet, dst)
        time.sleep(0.05)

    finished_at = time.time()
    total_duration = max(finished_at - started_at, 1e-9)
    stats = {
        "role": "p1",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": total_duration,
        "slot_interval_seconds": args.interval,
        "legit_bytes": legit_bytes,
        "legit_chunks": len(legit_chunks),
        "covert_bits_total": len(hidden_bits),
        "covert_bytes_payload": hidden_bytes,
        "covert_goodput_bps": (hidden_bytes * 8) / total_duration,
        "legit_goodput_Bps": legit_bytes / total_duration,
        "high_symbol_packet_count": HIGH_COUNT,
        "low_symbol_packet_count": LOW_COUNT,
        "threshold": THRESHOLD,
    }
    with open(args.stats_file, "w", encoding="utf-8") as stats_file:
        json.dump(stats, stats_file, indent=2)
    print(f"[P1] stats saved to {args.stats_file}")
    print("[P1] transmission completed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[P1] stopped")
        sys.exit(0)
