<!--
SPDX-FileCopyrightText: 2026 TSUKUMO Akito <tsukumoakito99@duck.com>
SPDX-License-Identifier: MIT
-->

<p align="center">
  <img src="doc/dns_stream_logo.svg" width="100%" alt="DNS Stream Logo">
</p>

# DNS Stream (Unified real-time DNS log stream and visualization engine)

[日本語版のREADMEはこちら (Japanese version available here)](./README_ja.md)

[![Zig Version](https://img.shields.io/badge/Zig-0.16.0-orange.svg)](https://ziglang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**DNS Stream** is a high-performance, terminal-based hybrid DNS traffic observer. It bridges the gap between static query logs and real-time Web APIs to provide a high-density, secure stream of DNS activity directly in your console.

Built with **Zig 0.16.0**, it leverages non-blocking I/O and a custom network engine to ensure "the only truth" of your network traffic is visible without ever needing to open a web browser.

---

## 💎 Key Pillars

### 1. Hybrid Observation Engine

Unlike traditional log tailers, `DNS Stream` operates in a dual-phase mode:

- **Historical Recovery**: Fast-scans local `querylog.json` via memory mapping (`mmap`) to recover recent past events.
- **Real-time Synchronization**: Seamlessly transitions to AdGuardHome Web APIs, using a sliding window and hash-based deduplication (`SeenBuffer`) to maintain a jitter-free live stream.

### 2. The Sniper Network Engine

A proprietary network hook system that ensures connectivity even in complex environments:

- **TLS Identity Snipe**: Directly identifies domain names from TLS certificates during the handshake, even when DNS resolution is obscured.
- **Proxy Matrix**: Full support for SOCKS5 and HTTP CONNECT tunnels, with integrated identity pinning to prevent man-in-the-middle leakage.
- **Zero-Trust Validation**: Pre-verifies communication paths using the `--network-probe` diagnostic suite.

### 3. Secure Vault & Kernel Integration

Security is not an afterthought. `DNS Stream` treats credentials as volatile secrets:

- **GPG/Pass Support**: Integrates with `.password-store` to decrypt credentials on-the-fly.
- **Linux Keyring**: Temporarily caches secrets in the Linux kernel keyring with strict process-only permissions.
- **Memory Safety**: Uses `mlock` and `secureZero` to ensure passwords never leak to swap space or remain in RAM after authentication.

---

## 🛠 Prerequisites

- **Zig 0.16.0** (Required for `std.Io` and `std.http` features)
- **GnuPG / GPGME** (For secure vault integration)
- **scdoc** (Optional, for generating man pages)

---

## 🚀 Installation

### 1. Arch Linux & Derivatives (AUR)

If you are using Arch Linux or an Arch-based distribution (e.g., Manjaro, EndeavourOS), the most reliable way to install is via the **AUR (Arch User Repository)**:

| Package | Version | Description | Votes | Links |
| :--- | :--- | :--- | :--- | :--- |
| **dns-stream** | ![AUR version](https://img.shields.io/aur/version/dns-stream) | Unified real-time DNS log stream | ![AUR votes](https://img.shields.io/aur/votes/dns-stream) | [![AUR](https://img.shields.io/badge/AUR-Package-orange)](https://aur.archlinux.org/packages/dns-stream) [![License](https://img.shields.io/aur/license/dns-stream)](./LICENSE) |

Install using an AUR helper:

```bash
# Using yay
yay -S dns-stream

# Using paru
paru -S dns-stream
```

### 2. Build from source

```bash
make build
sudo make install
```

---

## 📖 Documentation

- **Man Pages**: Unix/Linux/macOS users can refer to `man dns-stream` for terminal-native documentation.
- **Local Manual (Build Output)**: After running `zig build`, copies of the manual are available in `zig-out/doc/`. This is recommended for environments without `man` (e.g., native Windows).
- **Full Manual (Repository Source)**: For web-friendly reading or deep dive:
  - [User Manual (English)](./doc/MANUAL.md)
  - [User Manual (Japanese)](./doc/MANUAL_ja.md)

---

## ⌨️ Basic Usage

Standard execution using defaults (reads from `/etc/dns-stream/config.json`):

```bash
dns-stream
```

### Secure Vault Mode

Retrieve AdGuardHome password from your GPG-encrypted password store:

```bash
dns-stream --vault "home/adguard/admin_pass"
```

### Historical Analysis

Start streaming from a specific point in time:

```bash
dns-stream --start "2026-01-01T00:00:00"
```

### Network Matrix Probe

Verify your proxy and TLS connectivity before starting the stream:

```bash
dns-stream --network-probe --debug
```

---

## 🗺 Roadmap

`DNS Stream` is actively evolving as a universal DNS observation relay.

- [ ] **Remote API Expansion**: Full support for remote (Non-127.0.0.1) AdGuardHome instances with persistent authentication handshaking.
- [ ] **Pi-hole Ecosystem Support**: Integration of Pi-hole FTL APIs and long-term database streaming.
- [ ] **Multi-Instance Aggregation**: Ability to merge streams from multiple DNS nodes into a single unified terminal view.
- [ ] **Advanced Filtering DSL**: Complex query logic (e.g., "show only blocked requests from subnet X that resolved to IP Y").

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
