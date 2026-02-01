#!/usr/bin/env python3
"""
Convert bt-hci defmt btsnoop output to .log files for Wireshark analysis.

This script parses defmt output containing btsnoop packet records and converts
them into a standard btsnoop file format that can be opened in Wireshark.

Usage:
    # From a log file (outputs to capture.log by default):
    python btsnoop-convert.py tools/log.txt

    # With explicit output:
    python btsnoop-convert.py tools/log.txt -o capture.log

    # From stdin:
    cat defmt_output.log | python btsnoop-convert.py -o capture.log

    # Then open in Wireshark:
    wireshark capture.log

The script looks for lines containing:
    BTSNOOP:H:[...] - File header (16 bytes)
    BTSNOOP:P:[...]:[...] - Packet record (24-byte header + data)

All other lines are ignored.
"""

import sys
import re
import argparse


def parse_defmt_array(array_str: str) -> bytes:
    """
    Parse a defmt array string like '[00, 01, 02, ff]' into bytes.

    Handles formats:
    - [00, 01, 02] - comma-separated hex with brackets
    - 00 01 02 - space-separated hex
    - 000102 - plain hex string
    """
    # Remove brackets if present
    array_str = array_str.strip()
    if array_str.startswith('[') and array_str.endswith(']'):
        array_str = array_str[1:-1]

    # Split by comma or space
    if ',' in array_str:
        parts = [p.strip() for p in array_str.split(',')]
    elif ' ' in array_str:
        parts = array_str.split()
    else:
        # Plain hex string - split into pairs
        parts = [array_str[i:i+2] for i in range(0, len(array_str), 2)]

    # Convert each part to a byte
    result = []
    for p in parts:
        p = p.strip()
        if p:
            result.append(int(p, 16))

    return bytes(result)


def extract_btsnoop_data(line: str) -> tuple[str, bytes] | None:
    """
    Extract btsnoop data from a log line.

    Returns:
        Tuple of (record_type, data) where record_type is 'H' for header
        or 'P' for packet, or None if the line doesn't contain btsnoop data.
    """
    # Header pattern: BTSNOOP:H:[...]
    header_match = re.search(r'BTSNOOP:H:(\[[^\]]+\])', line)
    if header_match:
        try:
            data = parse_defmt_array(header_match.group(1))
            if len(data) >= 16:
                return ('H', data[:16])
        except (ValueError, IndexError):
            pass

    # Packet pattern: BTSNOOP:P:[...]:[...]
    # Match two bracketed arrays separated by a colon
    packet_match = re.search(r'BTSNOOP:P:(\[[^\]]+\]):(\[[^\]]*\])', line)
    if packet_match:
        try:
            header = parse_defmt_array(packet_match.group(1))
            data_str = packet_match.group(2)
            # Handle empty data array []
            if data_str.strip() == '[]':
                data = b''
            else:
                data = parse_defmt_array(data_str)
            if len(header) >= 24:
                return ('P', header[:24] + data)
        except (ValueError, IndexError) as e:
            print(f"Warning: Failed to parse packet: {e}", file=sys.stderr)
            pass

    return None


def convert_btsnoop(input_stream, output_stream, verbose: bool = False):
    """
    Convert defmt btsnoop output to .btsnoop file format.

    Args:
        input_stream: Input stream containing defmt log output
        output_stream: Binary output stream for .btsnoop file
        verbose: Print progress information to stderr
    """
    header_written = False
    packet_count = 0

    for line_num, line in enumerate(input_stream, 1):
        result = extract_btsnoop_data(line.strip())
        if result is None:
            continue

        record_type, data = result

        if record_type == 'H':
            if header_written:
                if verbose:
                    print(f"Warning: Multiple headers found, ignoring at line {line_num}", file=sys.stderr)
                continue
            output_stream.write(data)
            header_written = True
            if verbose:
                print(f"Wrote file header", file=sys.stderr)

        elif record_type == 'P':
            if not header_written:
                if verbose:
                    print(f"No header found, writing default header", file=sys.stderr)
                # Write default header: btsnoop\0 + version 1 + datalink 1002
                default_header = b'btsnoop\x00' + (1).to_bytes(4, 'big') + (1002).to_bytes(4, 'big')
                output_stream.write(default_header)
                header_written = True

            output_stream.write(data)
            packet_count += 1
            if verbose and packet_count % 100 == 0:
                print(f"Processed {packet_count} packets...", file=sys.stderr)

    if verbose:
        print(f"Conversion complete: {packet_count} packets written", file=sys.stderr)

    return packet_count


def main():
    parser = argparse.ArgumentParser(
        description='Convert bt-hci defmt btsnoop output to .btsnoop files',
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Print progress information to stderr'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Output file (default: capture.log, or <input_basename>.log if input specified)'
    )
    parser.add_argument(
        'input',
        type=str,
        nargs='?',
        default=None,
        help='Input file (default: stdin)'
    )

    args = parser.parse_args()

    # Open input
    if args.input:
        input_stream = open(args.input, 'r')
    else:
        input_stream = sys.stdin

    # Determine output filename
    output_file = args.output
    if output_file is None:
        if args.input:
            # Use input basename with .log extension
            import os
            base = os.path.splitext(os.path.basename(args.input))[0]
            output_file = f"{base}.btsnoop.log"
        else:
            output_file = "capture.log"

    # Open output
    output_stream = open(output_file, 'wb')
    if args.verbose:
        print(f"Writing to: {output_file}", file=sys.stderr)

    try:
        packet_count = convert_btsnoop(input_stream, output_stream, verbose=args.verbose)
        if packet_count == 0:
            print("Warning: No btsnoop data found in input", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Wrote {packet_count} packets to {output_file}", file=sys.stderr)
    finally:
        if args.input:
            input_stream.close()
        output_stream.close()


if __name__ == '__main__':
    main()
