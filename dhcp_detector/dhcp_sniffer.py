#!/usr/bin/env python3
"""
Passive DHCP sniffer for Home Assistant presence detection.

Listens for DHCP DISCOVER, REQUEST, and INFORM packets on a raw socket,
matches source MACs against a configured device list, and reports presence
state to Home Assistant via the Supervisor REST API (device_tracker/see).
"""

import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
ETHERTYPE_IPV4 = 0x0800
IP_PROTO_UDP = 17
BOOTP_MAGIC_COOKIE = 0x63825363

# DHCP message type option values (option 53)
DHCP_DISCOVER = 1
DHCP_REQUEST = 3
DHCP_INFORM = 8
TRACKED_MSG_TYPES = {DHCP_DISCOVER, DHCP_REQUEST, DHCP_INFORM}
MSG_TYPE_NAMES = {DHCP_DISCOVER: "DISCOVER", DHCP_REQUEST: "REQUEST", DHCP_INFORM: "INFORM"}

# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------

def parse_dhcp_packet(data: bytes):
    """Parse a raw Ethernet frame.

    Returns ``(mac_str, dhcp_message_type)`` for valid DHCP client packets,
    or ``None`` if the frame is not a DHCP client packet.
    """
    # --- Ethernet header (14 bytes) ---
    if len(data) < 14:
        return None
    ethertype = struct.unpack_from("!H", data, 12)[0]
    if ethertype != ETHERTYPE_IPV4:
        return None

    # --- IPv4 header ---
    ip_start = 14
    if len(data) < ip_start + 20:
        return None
    ip_ihl = (data[ip_start] & 0x0F) * 4
    ip_proto = data[ip_start + 9]
    if ip_proto != IP_PROTO_UDP:
        return None

    # --- UDP header (8 bytes) ---
    udp_start = ip_start + ip_ihl
    if len(data) < udp_start + 8:
        return None
    src_port = struct.unpack_from("!H", data, udp_start)[0]
    dst_port = struct.unpack_from("!H", data, udp_start + 2)[0]
    if src_port != DHCP_CLIENT_PORT or dst_port != DHCP_SERVER_PORT:
        return None

    # --- BOOTP / DHCP payload ---
    # Fixed BOOTP header: 236 bytes; magic cookie: 4 bytes → 240 bytes minimum.
    bootp_start = udp_start + 8
    if len(data) < bootp_start + 240:
        return None

    # op == 1: BOOTREQUEST (client → server)
    if data[bootp_start] != 1:
        return None

    # Client hardware address (MAC) is at offset 28 inside BOOTP, 6 bytes.
    mac_start = bootp_start + 28
    mac_bytes = data[mac_start : mac_start + 6]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)

    # Validate magic cookie.
    magic = struct.unpack_from("!I", data, bootp_start + 236)[0]
    if magic != BOOTP_MAGIC_COOKIE:
        return None

    # --- Parse DHCP options to find message type (option 53) ---
    dhcp_type = None
    idx = bootp_start + 240
    end = len(data)
    while idx < end:
        opt_code = data[idx]
        if opt_code == 255:  # End
            break
        if opt_code == 0:    # Pad
            idx += 1
            continue
        if idx + 1 >= end:
            break
        opt_len = data[idx + 1]
        if idx + 2 + opt_len > end:
            break
        if opt_code == 53 and opt_len == 1:
            dhcp_type = data[idx + 2]
        idx += 2 + opt_len

    if dhcp_type is None:
        return None

    return mac, dhcp_type


# ---------------------------------------------------------------------------
# Home Assistant Supervisor API
# ---------------------------------------------------------------------------

HA_SERVICE_URL = "http://supervisor/homeassistant/api/services/device_tracker/see"


def report_presence(token: str, mac: str, dev_id: str, location: str) -> bool:
    """POST a device_tracker/see call to HA via the Supervisor proxy.

    Returns True on success, False on error.
    """
    payload = json.dumps({"mac": mac, "dev_id": dev_id, "location_name": location}).encode()
    req = urllib.request.Request(
        HA_SERVICE_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        logging.error("HTTP error reporting %s (%s): %s %s", dev_id, mac, exc.code, exc.reason)
    except urllib.error.URLError as exc:
        logging.error("URL error reporting %s (%s): %s", dev_id, mac, exc.reason)
    except OSError as exc:
        logging.error("Error reporting %s (%s): %s", dev_id, mac, exc)
    return False


# ---------------------------------------------------------------------------
# Away timeout checker
# ---------------------------------------------------------------------------

def away_checker(token: str, device_map: dict, last_seen: dict, lock: threading.Lock, away_timeout: int):
    """Background daemon: mark devices as not_home after away_timeout seconds of silence."""
    while True:
        time.sleep(30)
        now = time.time()
        timed_out = []
        with lock:
            for mac, ts in list(last_seen.items()):
                if now - ts > away_timeout:
                    timed_out.append((mac, now - ts))
            for mac, elapsed in timed_out:
                last_seen.pop(mac, None)

        for mac, elapsed in timed_out:
            name = device_map.get(mac, mac)
            logging.info(
                "%s  AWAY  %s (%s) — no DHCP seen for %.0fs → not_home",
                time.strftime("%Y-%m-%d %H:%M:%S"),
                name,
                mac,
                elapsed,
            )
            report_presence(token, mac, name, "not_home")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )

    # Load add-on options written by the Supervisor.
    options_path = "/data/options.json"
    try:
        with open(options_path) as fh:
            options = json.load(fh)
    except FileNotFoundError:
        logging.error("Options file not found: %s", options_path)
        sys.exit(1)

    interface = options.get("interface", "eth0")
    away_timeout = int(options.get("away_timeout", 600))
    devices = options.get("devices", [])

    token = os.environ.get("SUPERVISOR_TOKEN", "")
    if not token:
        logging.error("SUPERVISOR_TOKEN environment variable is not set. "
                      "Ensure homeassistant_api is enabled in config.yaml.")
        sys.exit(1)

    # Build MAC → friendly-name mapping; normalise MACs to lowercase colon-separated.
    device_map: dict[str, str] = {}
    for dev in devices:
        mac = dev["mac"].lower().replace("-", ":").strip()
        device_map[mac] = dev["name"]

    logging.info("DHCP Detector starting — interface=%s, away_timeout=%ds, tracking %d device(s)",
                 interface, away_timeout, len(device_map))
    for mac, name in device_map.items():
        logging.info("  tracking: %s → %s", mac, name)

    # last_seen tracks the timestamp of the most recent DHCP packet per MAC.
    last_seen: dict[str, float] = {}
    lock = threading.Lock()

    # Start away-timeout background thread.
    t = threading.Thread(
        target=away_checker,
        args=(token, device_map, last_seen, lock, away_timeout),
        daemon=True,
    )
    t.start()

    # Open a raw AF_PACKET socket bound to the chosen interface.
    # We filter for IPv4 (ETH_P_IP = 0x0800) at the socket level to reduce noise.
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV4))
        sock.bind((interface, 0))
    except PermissionError:
        logging.error("Permission denied opening raw socket. Ensure CAP_NET_RAW is granted.")
        sys.exit(1)
    except OSError as exc:
        logging.error("Failed to open raw socket on %s: %s", interface, exc)
        sys.exit(1)

    logging.info("Listening on %s …", interface)

    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except OSError as exc:
            logging.error("Socket read error: %s", exc)
            time.sleep(1)
            continue

        result = parse_dhcp_packet(data)
        if result is None:
            continue

        mac, dhcp_type = result
        if dhcp_type not in TRACKED_MSG_TYPES:
            continue
        if mac not in device_map:
            continue

        name = device_map[mac]
        type_name = MSG_TYPE_NAMES.get(dhcp_type, str(dhcp_type))
        logging.info(
            "%s  DHCP %-8s  %s (%s) → home",
            time.strftime("%Y-%m-%d %H:%M:%S"),
            type_name,
            name,
            mac,
        )

        with lock:
            last_seen[mac] = time.time()
        report_presence(token, mac, name, "home")


if __name__ == "__main__":
    main()
