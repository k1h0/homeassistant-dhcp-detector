# DHCP Detector — Home Assistant Add-on

Passive DHCP sniffing for presence detection.  
The add-on monitors DHCP traffic on the host network interface and reports device
presence directly to Home Assistant via the Supervisor REST API, creating one
`device_tracker` entity per tracked device — no MQTT, no extra integrations, no
manual YAML required.

---

## How it works

1. A raw `AF_PACKET` socket listens for DHCP **DISCOVER**, **REQUEST**, and **INFORM**
   packets sent by devices on the local network.
2. The source MAC address in each packet is matched against your configured device list.
3. On a match the add-on calls the Supervisor REST API:
   ```
   POST http://supervisor/homeassistant/api/services/device_tracker/see
   { "mac": "…", "dev_id": "…", "location_name": "home" }
   ```
   HA creates the `device_tracker.<name>` entity automatically on the first call.
4. If no DHCP packet is seen from a device within the configured **away timeout**
   (default 600 s / 10 min), the device is reported as `not_home`.

The add-on never transmits any DHCP packets and never interferes with your existing
DHCP server.

---

## Installation

1. In Home Assistant, go to **Settings → Add-ons → Add-on store**.
2. Click the **⋮** menu (top-right) and choose **Repositories**.
3. Add the URL of this repository, then click **Add**.
4. Find **DHCP Detector** in the store and click **Install**.
5. Configure the add-on (see [Options](#options) below), then click **Start**.

Alternatively, copy the `dhcp_detector/` directory into your
`/addons/` folder on the Home Assistant OS file system (local add-on install).

---

## Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interface` | `string` | `eth0` | Network interface to listen on (e.g. `eth0`, `enp3s0`). |
| `away_timeout` | `integer` | `600` | Seconds without a DHCP packet before a device is marked `not_home`. |
| `devices` | `list` | `[]` | List of `{ mac, name }` pairs to track (see below). |

### Devices list example

```yaml
devices:
  - mac: "aa:bb:cc:dd:ee:ff"
    name: "alice_phone"
  - mac: "11:22:33:44:55:66"
    name: "bob_laptop"
```

* `mac` — the device's MAC address (colon- or hyphen-separated, case-insensitive).  
  For iOS devices that use **Private Wi-Fi Address**, use the per-network stable MAC
  shown in the Wi-Fi details for your home network.
* `name` — used as the `dev_id` in Home Assistant. The resulting entity will be
  `device_tracker.<name>`.

---

## Notes

* The add-on requires **host networking** (`host_network: true`) and the `NET_RAW`
  Linux capability so it can open a raw socket.  Both are configured automatically.
* The `SUPERVISOR_TOKEN` environment variable is injected automatically by the
  Supervisor — no credentials need to be entered.
* Presence latency is typically 1–3 seconds from when a device (re-)joins the network.
* The away-timeout checker runs every 30 seconds, so actual `not_home` reporting may
  lag up to 30 seconds behind the timeout expiry.
