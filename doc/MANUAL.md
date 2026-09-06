<!--
SPDX-FileCopyrightText: 2026 TSUKUMO Akito <tsukumoakito99@duck.com>
SPDX-License-Identifier: MIT
-->

# DNS Stream User Manual (v1.0.2 / 2026-09-07)

**DNS Stream** is a specialized hybrid relay and visualization engine designed to provide a real-time, high-fidelity stream of DNS traffic. It is optimized for AdGuardHome (AGH) environments and implements advanced networking hooks to ensure observability even through complex proxy chains.

---

## 1. Core Architecture

### 1.1 Hybrid Observation Engine

`DNS Stream` does not rely on a single data source. It operates in two distinct phases:

1. **Historical Recovery (File Mode)**: On startup, it uses memory-mapping (`mmap`) to instantly scan the local `querylog.json`. This populates the terminal with recent history without stressing the CPU.
2. **Live Synchronization (API Mode)**: After processing the log file, it transitions to the AdGuardHome Web API. It uses a sliding window and a hash-based `SeenBuffer` to ensure no log entry is missed or duplicated, even if the API polling interval fluctuates.

### 1.2 The Sniper Network Engine

The "Sniper" engine is a proprietary networking layer built into `DNS Stream` that intercepts connection attempts to perform deep inspections:

- **TLS Identity Snipe**: If a target is identified only by an IP address (common in proxied environments), the engine performs a binary-level TLS handshake to extract the Subject Alternative Name (SAN) from the certificate, pinning the correct identity.
- **Handshake Guard**: When using proxies, the engine validates that the tunnel is truly established before sending sensitive credentials, preventing data leakage to misconfigured proxy servers.

---

## 2. Security and Authentication

### 2.1 GPG / Password-Store Integration

Instead of passing passwords via plaintext flags, `DNS Stream` integrates with `pass` (the standard Unix password manager). By providing a vault path, the tool communicates with `gpg-agent` to decrypt credentials in-memory.

### 2.2 Linux Kernel Keyring

Once a password is recovered from the vault or user prompt, it is temporarily stored in the **Linux Process Keyring**.

- The secret is locked in memory (`mlock`) to prevent it from being swapped to disk.
- The keyring entry is restricted to the specific `dns-stream` process ID and is cleared upon termination.

### 2.3 Privilege Management

When starting as `root` (often necessary to read `/var/lib/adguardhome/`), `DNS Stream` can drop its privileges to a standard user using the `--drop-user` flag immediately after gaining access to the required file descriptors.

---

## 3. Command Line Interface

### 3.1 General Flags

- `--config <path>`: Load a custom JSON configuration.
- `--log-path <path>`: Path to the AGH query log (Default: `/var/lib/adguardhome/data/querylog.json`).
- `--log-mode <auto|force|disable>`:
    - `auto`: Hybrid (Scan file, then poll API).
    - `force`: File scan only.
    - `disable`: API polling only.
- `--start <timestamp>`: Start logs from a specific time (Format: `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`).
- `--polling <seconds>`: Speed of API checks (Default: `1.0`).

### 3.2 Filtering

- `--ip <pattern>`: Show only specific clients (e.g., `--ip "192.168.1.*"`).
- `--name <string>`: Filter by client name or domain (e.g., `--name "apple.com"`).

### 3.3 Diagnostic Suite

- `--network-probe`: Execute a full test of the connection matrix. It verifies DNS resolution, Proxy handshake, and TLS identity recovery.
- `--debug-mem`: Displays a real-time memory usage footer, useful for long-term monitoring on embedded devices.

---

## 4. Configuration (config.json)

The configuration file allows for permanent settings and custom visualization rules:

```json
{
  "api_url": "http://127.0.0.1:80",
  "user": "admin",
  "vault_path": "services/dns/agh_admin",
  "polling_s": 1.0,
  "colors": {
    "127.0.0.1": "gray",
    "192.168.1.*": "blue",
    "10.0.0.*": "cyan"
  }
}
```

- `colors`: Maps IP CIDR/Wildcard patterns to ANSI colors (`red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `gray`, `dim`, `bold`).

---

## 5. Roadmap and Known Limits

### 5.1 Roadmap

- **Remote Instance Stability**: Improving the persistent handshake logic for AGH instances hosted on remote VPS (currently optimized for local loopback).
- **Pi-hole Integration**: Adding support for Pi-hole FTL APIs using the same Sniper engine.
- **Unified View**: Aggregating logs from multiple DNS servers into a single chronological stream.

### 5.2 Current Restrictions

- Currently requires AdGuardHome.
- Direct API connection to external (non-local) IP addresses may experience session timeouts in high-latency environments (Fix in progress).

---

## 6. Troubleshooting

If you see no logs appearing:

1. Run `dns-stream --network-probe` to check if the tool can reach the API.
2. Ensure your user has read permissions for the `querylog.json` file.
3. Check if `gpg-agent` is running if using `--vault`.

For more details, visit the repository: [https://codeberg.org/tsukumoakito/dns-stream](https://codeberg.org/tsukumoakito/dns-stream)
