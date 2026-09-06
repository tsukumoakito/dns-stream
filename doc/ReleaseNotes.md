<!--
SPDX-FileCopyrightText: 2026 TSUKUMO Akito <tsukumoakito99@duck.com>
SPDX-License-Identifier: MIT
-->

# v1.0.2: The Hybrid Observer Genesis

We are pleased to announce the initial release of **DNS Stream v1.0.2**.
This version marks the birth of a dedicated high-fidelity DNS traffic observer, designed to extract the "Ground Truth" of network activity through a unique hybrid architectural approach.

> **Note:** v1.0.2 establishes the foundation of our "Sniper" network engine, ensuring that DNS observability remains intact even across complex proxy-layered infrastructures.

## 🚀 Strategic Milestone: Hybrid Observability

`DNS Stream` is built on the philosophy that logs should be immediate, accurate, and secure. Version 1.0.2 introduces the **Hybrid Discovery Mode**, which bridges the gap between cold storage and live streams. By instantly recovering past events via memory-mapped local files and then hot-swapping to real-time Web APIs, it provides a seamless timeline of network truth without the latency of traditional polling.

## ✨ Key Features of DNS Stream

- **Sniper Network Engine**: A custom networking layer capable of "Binary Sniping"—extracting domain identities directly from TLS handshakes. This ensures accurate logging even when DNS resolution is performed behind remote proxies.
- **Hybrid Data Sourcing**: Optimized memory-mapped (`mmap`) file scanning for AdGuardHome `querylog.json` coupled with high-concurrency API polling.
- **Secure Vault Integration**: Native support for GPG-encrypted `.password-store` and the **Linux Kernel Keyring** (via `add_key`/`keyctl`), ensuring credentials never touch the disk or remain exposed in process memory.
- **Real-time Diagnostic Suite**: Integrated `--network-probe` utility to verify the integrity of the network matrix (DNS/Proxy/TLS) before establishing the stream.

## 🛠 Technical Environment: Zig 0.16.0

`DNS Stream` is built to lead the transition into the latest language ecosystem. By utilizing **Zig 0.16.0**, we leverage the finalized `std.Io` and `std.http` architectures to achieve maximum throughput with minimal resource overhead. This release is optimized for non-blocking asynchronous operations.

## 📦 Installation

For Arch Linux users, `dns-stream` is available via **AUR**:

```bash
yay -S dns-stream
```

For other environments, use the provided **Makefile**:

```bash
make build && sudo make install
```

## 🗺 Roadmap Highlights

As this is the genesis release, we are looking forward to:

- **Remote Instance Resilience**: Finalizing persistent handshake logic for non-local AdGuardHome nodes.
- **Pi-hole Expansion**: Bringing the same Sniper-based observability to the Pi-hole/FTL ecosystem.

---

**DNS Stream v1.0.2 リリースのお知らせ**

ハイパフォーマンスなDNSトラフィック・オブザーバーである **DNS Stream v1.0.2** の初回リリースをご報告いたします。本バージョンは、独自のハイブリッド・アーキテクチャを通じて、ネットワーク・アクティビティの「唯一の真実（Ground Truth）」を抽出するための新たな基準を確立します。

> **補足:** v1.0.2 は、当プロジェクトのコアである「スナイパー」ネットワークエンジンの基盤を構築し、複雑なプロキシ階層が存在する環境下でもDNSの観測性を損なわない仕組みを提供します。

## 🚀 戦略的マイルストーン：ハイブリッド・オブザべビリティ

`DNS Stream` は、ログは即時的で正確、かつセキュアであるべきだという哲学に基づいています。v1.0.2 では、コールドストレージとライブストリームの溝を埋める **ハイブリッド・ディスカバリー・モード** を導入しました。メモリマッピングされたローカルファイルから過去のイベントを即座に復元し、リアルタイムWeb APIへホットスワップすることで、従来のポーリングのような遅延を感じさせないシームレスなネットワーク監視を実現します。

## ✨ DNS Stream の主な特徴

- **スナイパー・ネットワーク・エンジン**: TLSハンドシェイクからドメインのアイデンティティを直接抽出する「バイナリ・スナイピング」機能を搭載。リモートプロキシ越しにDNS解決が行われる環境でも、正確なロギングを保証します。
- **ハイブリッド・データソース**: AdGuardHome の `querylog.json` に対する最適化された `mmap` スキャンと、高並列なAPIポーリングの統合。
- **セキュア・ヴォルト統合**: GPG暗号化された `.password-store` および **Linux カーネル・キーリング** (`add_key`/`keyctl`) をネイティブサポート。資格情報をディスクに書き込まず、プロセスメモリ内でも露出を最小限に抑えます。
- **リアルタイム診断スイート**: ストリーム開始前にネットワークマトリクス（DNS/Proxy/TLS）の整合性を検証する `--network-probe` ユーティリティを内蔵。

## 🛠 技術環境：Zig 0.16.0

`DNS Stream` は、最新の言語エコシステムへの移行を先導します。 **Zig 0.16.0** を採用し、刷新された `std.Io` と `std.http` アーキテクチャを活用することで、最小のリソースオーバーヘッドで最大の同時処理能力を実現しました。

## 📦 インストール

Arch Linux ユーザーの方は、**AUR** から導入可能です：

```bash
yay -S dns-stream
```

その他の環境では、付属の **Makefile** を使用してください：

```bash
make build && sudo make install
```
