import argparse
import json
import socket
import struct
import sys
import time
from typing import Dict, List, Optional


HEADER_FORMAT = "!BBIH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
PKT_LEGIT = 0x01
PKT_END = 0x03
FLAG_LAST = 0x01
THRESHOLD = 5
ANCHOR_OFFSET_RATIO = 0.20


def parse_args():
    parser = argparse.ArgumentParser(
        description="receiver: decodes covert channel from packet intensity per slot"
    )
    parser.add_argument("--listen-ip", default="0.0.0.0", help="Local IP to listen on")
    parser.add_argument("--listen-port", type=int, default=9001, help="Local UDP port")
    parser.add_argument("--interval", type=float, default=1.0, help="Slot duration in seconds")
    parser.add_argument("--covert-output", default="recovered_covert.txt", help="Recovered hidden file")
    parser.add_argument("--legit-output", default="recovered_main.txt", help="Recovered legitimate file")
    parser.add_argument("--stats-file", default="p2_stats.json", help="Path to JSON file with receiver stats")
    return parser.parse_args()


def finalize_slot(packet_count: int, bit_buffer: List[int]) -> None:
    bit_buffer.append(1 if packet_count > THRESHOLD else 0)


def bits_to_bytes(bits: List[int]) -> bytes:
    out = bytearray()
    for idx in range(0, len(bits), 8):
        byte = 0
        for bit in bits[idx:idx + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def flush_legit_chunks(buffer: Dict[int, bytes], next_seq: int, out_file) -> int:
    while next_seq in buffer:
        out_file.write(buffer.pop(next_seq))
        out_file.flush()
        next_seq += 1
    return next_seq


def decode_covert(bit_stream: List[int]) -> Optional[bytes]:
    if len(bit_stream) < 32:
        return None
    length = int("".join(str(bit) for bit in bit_stream[:32]), 2)
    total_bits = 32 + length * 8
    if len(bit_stream) < total_bits:
        return None
    return bits_to_bytes(bit_stream[32:total_bits])


def decode_covert_partial(bit_stream: List[int]) -> bytes:
    if len(bit_stream) <= 32:
        return b""
    payload_bits = bit_stream[32:]
    whole_bytes = (len(payload_bits) // 8) * 8
    if whole_bytes == 0:
        return b""
    return bits_to_bytes(payload_bits[:whole_bytes])


def main():
    args = parse_args()
    if args.interval <= 0:
        raise SystemExit("[P2] interval must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_ip, args.listen_port))
    sock.settimeout(max(0.01, min(args.interval / 5.0, 0.2)))
    print(f"[P2] listening on {args.listen_ip}:{args.listen_port}")
    print(f"[P2] interval={args.interval}s, threshold={THRESHOLD}")

    bit_stream: List[int] = []
    legit_buffer: Dict[int, bytes] = {}
    next_legit_seq = 1
    legit_last_seq: Optional[int] = None
    covert_saved = False
    covert_bytes_recovered = 0
    covert_partial = False
    legit_bytes_written = 0
    total_packets = 0
    legit_packets = 0

    start_ts: Optional[float] = None
    current_slot = 0
    current_count = 0
    end_received = False
    started_at = time.time()
    finished_at = started_at

    with open(args.legit_output, "wb") as legit_out:
        while True:
            now = time.monotonic()

            if start_ts is not None:
                elapsed_slots = int((now - start_ts) / args.interval)
                while current_slot < elapsed_slots:
                    finalize_slot(current_count, bit_stream)
                    print(f"[P2] slot={current_slot} packets={current_count} bit={bit_stream[-1]}")
                    current_slot += 1
                    current_count = 0
                    decoded = decode_covert(bit_stream)
                    if decoded is not None and not covert_saved:
                        with open(args.covert_output, "wb") as covert_out:
                            covert_out.write(decoded)
                        print(f"[P2] covert message saved to {args.covert_output}")
                        covert_saved = True
                        covert_bytes_recovered = len(decoded)

            if end_received:
                if start_ts is not None:
                    finalize_slot(current_count, bit_stream)
                    print(f"[P2] slot={current_slot} packets={current_count} bit={bit_stream[-1]}")
                break

            try:
                data, src = sock.recvfrom(65535)
            except socket.timeout:
                continue

            recv_ts = time.monotonic()
            if start_ts is None:
                start_ts = recv_ts - args.interval * ANCHOR_OFFSET_RATIO
                print(f"[P2] first packet from {src[0]}:{src[1]}, timing origin initialized")

            slot = int((recv_ts - start_ts) / args.interval)
            while current_slot < slot:
                finalize_slot(current_count, bit_stream)
                print(f"[P2] slot={current_slot} packets={current_count} bit={bit_stream[-1]}")
                current_slot += 1
                current_count = 0
                decoded = decode_covert(bit_stream)
                if decoded is not None and not covert_saved:
                    with open(args.covert_output, "wb") as covert_out:
                        covert_out.write(decoded)
                    print(f"[P2] covert message saved to {args.covert_output}")
                    covert_saved = True
                    covert_bytes_recovered = len(decoded)

            if len(data) < HEADER_SIZE:
                continue

            packet_type, flags, seq, payload_len = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
            if packet_type == PKT_END:
                end_received = True
                finished_at = time.time()
                continue

            total_packets += 1
            current_count += 1
            payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]

            if packet_type == PKT_LEGIT:
                legit_packets += 1
                legit_buffer[seq] = payload
                legit_bytes_written += len(payload)
                next_legit_seq = flush_legit_chunks(legit_buffer, next_legit_seq, legit_out)
                if flags & FLAG_LAST:
                    legit_last_seq = seq
                print(f"[P2] legit packet seq={seq}, payload_len={payload_len}")

        if legit_last_seq is not None and next_legit_seq - 1 == legit_last_seq:
            print(f"[P2] legitimate file saved to {args.legit_output}")
        else:
            print("[P2] legitimate stream ended with missing packets or without last marker")

        decoded = decode_covert(bit_stream)
        if decoded is None:
            partial = decode_covert_partial(bit_stream)
            if partial:
                with open(args.covert_output, "wb") as covert_out:
                    covert_out.write(partial)
                covert_bytes_recovered = len(partial)
                covert_partial = True
                print(f"[P2] covert message partially saved to {args.covert_output}")
            else:
                print("[P2] covert message not recovered")
        elif not covert_saved:
            with open(args.covert_output, "wb") as covert_out:
                covert_out.write(decoded)
            print(f"[P2] covert message saved to {args.covert_output}")
            covert_bytes_recovered = len(decoded)

    if not end_received:
        finished_at = time.time()

    total_duration = max(finished_at - started_at, 1e-9)
    covert_complete = decode_covert(bit_stream) is not None
    stats = {
        "role": "p2",
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": total_duration,
        "slot_interval_seconds": args.interval,
        "total_packets_received": total_packets,
        "legit_packets_received": legit_packets,
        "legit_bytes_received": legit_bytes_written,
        "legit_stream_complete": legit_last_seq is not None and next_legit_seq - 1 == legit_last_seq,
        "legit_goodput_Bps": legit_bytes_written / total_duration,
        "covert_bits_observed": len(bit_stream),
        "covert_bytes_recovered": covert_bytes_recovered,
        "covert_complete": covert_complete,
        "covert_partial": covert_partial,
        "covert_goodput_bps": (covert_bytes_recovered * 8) / total_duration,
        "threshold": THRESHOLD,
    }
    with open(args.stats_file, "w", encoding="utf-8") as stats_file:
        json.dump(stats, stats_file, indent=2)
    print(f"[P2] stats saved to {args.stats_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[P2] stopped")
        sys.exit(0)
