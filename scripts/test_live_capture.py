"""Simple standalone script to test live capture with TShark and PyShark."""

from __future__ import annotations

import subprocess

import pyshark
from pyshark.tshark.tshark import TSharkNotFoundException


def main() -> None:
    """List interfaces and attempt a 10-packet live capture on Wi-Fi."""
    print("Listing interfaces with tshark -D...")
    interfaces = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=False)
    if interfaces.stdout:
        print(interfaces.stdout)
    if interfaces.stderr:
        print(interfaces.stderr)

    print('Starting live capture on "Wi-Fi"...')
    packet_count = 0
    capture = pyshark.LiveCapture(interface="Wi-Fi")
    try:
        for packet in capture.sniff_continuously():
            packet_count += 1
            print(packet)
            if packet_count >= 10:
                break
        if packet_count == 10:
            print("Capture successful")
        else:
            print(f"Capture ended after {packet_count} packets")
    finally:
        capture.close()


if __name__ == "__main__":
    try:
        main()
    except TSharkNotFoundException:
        print("Error: TShark not found. Please install Wireshark with TShark and ensure it is in PATH.")
    except Exception as exc:
        print(f"Error: {exc}")
