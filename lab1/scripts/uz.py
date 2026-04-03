import argparse
import socket
import sys


def parse_args():
    parser = argparse.ArgumentParser(description="UDP proxy for the covert-channel lab")
    parser.add_argument("--listen-ip", default="0.0.0.0", help="Local IP to listen on")
    parser.add_argument("--listen-port", type=int, default=9000, help="Local UDP port")
    parser.add_argument("--forward-ip", required=True, help="Destination IP")
    parser.add_argument("--forward-port", type=int, default=9001, help="Destination UDP port")
    return parser.parse_args()


def main():
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.listen_ip, args.listen_port))
    print(
        f"[UZ] forwarding UDP packets from {args.listen_ip}:{args.listen_port} "
        f"to {args.forward_ip}:{args.forward_port}"
    )

    while True:
        data, src = sock.recvfrom(65535)
        sock.sendto(data, (args.forward_ip, args.forward_port))
        print(f"[UZ] {len(data)} bytes from {src[0]}:{src[1]} forwarded")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[UZ] stopped")
        sys.exit(0)
