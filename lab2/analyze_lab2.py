from __future__ import annotations

import argparse
import math
import socket
import statistics
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_DUMP_PATH = ROOT / "dumps" / "4.pcapng"
DEFAULT_ASSETS_DIR = ROOT / "report_assets"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def parse_pcapng_timestamps(path: Path) -> list[int]:
    data = path.read_bytes()
    endian = "<"
    linktypes: list[int] = []
    timestamps: list[int] = []
    offset = 0

    while offset + 12 <= len(data):
        block_type = struct.unpack_from("<I", data, offset)[0]
        block_len = struct.unpack_from("<I", data, offset + 4)[0]
        if block_len < 12 or offset + block_len > len(data):
            break

        body = data[offset + 8 : offset + block_len - 4]

        if block_type == 0x0A0D0D0A:
            bom = body[:4]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        elif block_type == 1:
            linktype, _, _ = struct.unpack_from(endian + "HHI", body, 0)
            linktypes.append(linktype)
        elif block_type in (3, 6):
            interface_id, ts_high, ts_low, captured_len, _ = struct.unpack_from(
                endian + "IIIII", body, 0
            )
            packet = body[20 : 20 + captured_len]
            if linktypes[interface_id] == 0:
                packet = packet[4:]

            if len(packet) < 20 or (packet[0] >> 4) != 4:
                offset += block_len
                continue

            if packet[9] != 17:
                offset += block_len
                continue

            _ = socket.inet_ntoa(packet[12:16])
            _ = socket.inet_ntoa(packet[16:20])
            timestamps.append((ts_high << 32) | ts_low)

        offset += block_len

    return timestamps


def intervals_from_timestamps(timestamps: list[int]) -> list[float]:
    return [(timestamps[i] - timestamps[i - 1]) / 1_000_000 for i in range(1, len(timestamps))]


def histogram(intervals: list[float], bins: int = 20) -> dict[str, object]:
    low = min(intervals)
    high = max(intervals)
    width = (high - low) / bins
    counts = [0] * bins
    for value in intervals:
        index = min(int((value - low) / width), bins - 1)
        counts[index] += 1

    mean_value = statistics.mean(intervals)
    mean_index = min(int((mean_value - low) / width), bins - 1)
    c_max = max(counts)
    c_mu = counts[mean_index]
    probability = 1 - c_mu / c_max
    edges = [low + i * width for i in range(bins + 1)]

    return {
        "counts": counts,
        "edges": edges,
        "mean": mean_value,
        "mean_index": mean_index,
        "c_max": c_max,
        "c_mu": c_mu,
        "probability": probability,
        "bin_width": width,
    }


def render_histogram_svg(
    counts: list[int],
    edges: list[float],
    mean_index: int,
    title: str,
    output: Path,
) -> None:
    width = 980
    height = 560
    margin_left = 70
    margin_right = 20
    margin_top = 55
    margin_bottom = 80
    chart_width = width - margin_left - margin_right
    chart_height = height - margin_top - margin_bottom
    bins = len(counts)
    bar_gap = 4
    bar_width = (chart_width - bar_gap * (bins - 1)) / bins
    max_count = max(counts)

    bars: list[str] = []
    labels: list[str] = []
    grid: list[str] = []

    for level in range(0, max_count + 1, max(1, math.ceil(max_count / 6))):
        y = margin_top + chart_height - (level / max_count) * chart_height
        grid.append(
            f'<line x1="{margin_left}" y1="{y:.2f}" x2="{width - margin_right}" y2="{y:.2f}" '
            'stroke="#d7dde5" stroke-width="1" />'
        )
        labels.append(
            f'<text x="{margin_left - 10}" y="{y + 4:.2f}" text-anchor="end" '
            'font-size="12" fill="#334155">{level}</text>'
        )

    for i, count in enumerate(counts):
        x = margin_left + i * (bar_width + bar_gap)
        bar_height = 0 if max_count == 0 else (count / max_count) * chart_height
        y = margin_top + chart_height - bar_height
        fill = "#d94841" if i == mean_index else "#315c73"
        bars.append(
            f'<rect x="{x:.2f}" y="{y:.2f}" width="{bar_width:.2f}" height="{bar_height:.2f}" '
            f'fill="{fill}" rx="3" />'
        )
        center = x + bar_width / 2
        labels.append(
            f'<text x="{center:.2f}" y="{height - margin_bottom + 20}" text-anchor="middle" '
            f'font-size="10" fill="#334155">{edges[i]:.2f}</text>'
        )

    labels.append(
        f'<text x="{width / 2:.2f}" y="{height - 18}" text-anchor="middle" '
        'font-size="13" fill="#0f172a">Длина межпакетного интервала, с</text>'
    )
    labels.append(
        f'<text x="20" y="{height / 2:.2f}" text-anchor="middle" transform="rotate(-90 20 {height / 2:.2f})" '
        'font-size="13" fill="#0f172a">Число интервалов</text>'
    )
    labels.append(
        f'<text x="{width / 2:.2f}" y="28" text-anchor="middle" '
        'font-size="20" font-weight="700" fill="#0f172a">'
        f"{title}</text>"
    )

    mean_x = margin_left + mean_index * (bar_width + bar_gap) + bar_width / 2
    mean_line = (
        f'<line x1="{mean_x:.2f}" y1="{margin_top}" x2="{mean_x:.2f}" y2="{margin_top + chart_height}" '
        'stroke="#d94841" stroke-width="2" stroke-dasharray="6 4" />'
    )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" fill="#f8fafc" />
<text x="{width - 24}" y="28" text-anchor="end" font-size="12" fill="#475569">Красная линия: бин со средним μ</text>
<line x1="{margin_left}" y1="{margin_top + chart_height}" x2="{width - margin_right}" y2="{margin_top + chart_height}" stroke="#0f172a" stroke-width="2" />
<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + chart_height}" stroke="#0f172a" stroke-width="2" />
{''.join(grid)}
{mean_line}
{''.join(bars)}
{''.join(labels)}
</svg>
"""
    output.write_text(svg, encoding="utf-8")


def decode_message(intervals: list[float]) -> dict[str, object]:
    sorted_values = sorted(intervals)
    biggest_gap_index = max(
        range(len(sorted_values) - 1),
        key=lambda i: sorted_values[i + 1] - sorted_values[i],
    )
    threshold = (sorted_values[biggest_gap_index] + sorted_values[biggest_gap_index + 1]) / 2

    bits = "".join("0" if value < threshold else "1" for value in intervals)
    raw_bytes = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
    text = raw_bytes.decode("ascii")

    short_cluster = [value for value in intervals if value < threshold]
    long_cluster = [value for value in intervals if value >= threshold]

    return {
        "threshold": threshold,
        "bits": bits,
        "bytes": raw_bytes,
        "text": text,
        "short_count": len(short_cluster),
        "long_count": len(long_cluster),
        "short_mean": statistics.mean(short_cluster),
        "long_mean": statistics.mean(long_cluster),
        "short_min": min(short_cluster),
        "short_max": max(short_cluster),
        "long_min": min(long_cluster),
        "long_max": max(long_cluster),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dump",
        type=Path,
        default=DEFAULT_DUMP_PATH,
        help="Path to the pcapng dump file.",
    )
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=DEFAULT_ASSETS_DIR,
        help="Directory for generated histogram SVG files.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dump_path = args.dump.resolve()
    assets_dir = args.assets_dir.resolve()
    assets_dir.mkdir(exist_ok=True)

    timestamps = parse_pcapng_timestamps(dump_path)
    all_intervals = intervals_from_timestamps(timestamps)
    hidden_intervals = all_intervals[99:]

    all_hist = histogram(all_intervals)
    hidden_hist = histogram(hidden_intervals)
    decoded = decode_message(hidden_intervals)

    render_histogram_svg(
        all_hist["counts"],
        all_hist["edges"],
        all_hist["mean_index"],
        "Гистограмма межпакетных интервалов по всему дампу",
        assets_dir / "hist_all.svg",
    )
    render_histogram_svg(
        hidden_hist["counts"],
        hidden_hist["edges"],
        hidden_hist["mean_index"],
        "Гистограмма межпакетных интервалов после 100-го пакета",
        assets_dir / "hist_hidden.svg",
    )

    print(f"Дамп: {dump_path}")
    print(f"Пакетов UDP: {len(timestamps)}")
    print(f"Интервалов всего: {len(all_intervals)}")
    print(f"Интервалов после 100-го пакета: {len(hidden_intervals)}")
    print()
    print("Весь дамп:")
    print(f"  μ = {all_hist['mean']:.6f} с")
    print(f"  Cμ = {all_hist['c_mu']}, Cmax = {all_hist['c_max']}")
    print(f"  P = 1 - {all_hist['c_mu']}/{all_hist['c_max']} = {all_hist['probability']:.6f}")
    print()
    print("После 100-го пакета:")
    print(f"  μ = {hidden_hist['mean']:.6f} с")
    print(f"  Cμ = {hidden_hist['c_mu']}, Cmax = {hidden_hist['c_max']}")
    print(f"  P = 1 - {hidden_hist['c_mu']}/{hidden_hist['c_max']} = {hidden_hist['probability']:.6f}")
    print()
    print("Декодирование:")
    print(f"  Порог = {decoded['threshold']:.6f} с")
    print(
        f"  Короткий интервал: {decoded['short_mean']:.6f} с "
        f"({decoded['short_min']:.6f}..{decoded['short_max']:.6f}), бит 0"
    )
    print(
        f"  Длинный интервал:  {decoded['long_mean']:.6f} с "
        f"({decoded['long_min']:.6f}..{decoded['long_max']:.6f}), бит 1"
    )
    print(f"  Сообщение: {decoded['text']}")


if __name__ == "__main__":
    main()
