dns-stream(1) "1.0.2" "dns-stream ユーザマニュアル"

# 名前

dns-stream - 統合リアルタイムDNSログストリーム & 可視化エンジン

# 書式

*dns-stream* [オプション...]

# 説明

*dns-stream* は、AdGuardHome（および将来的に対応予定のDNSエンジン）向けの高性能なターミナル・
	オブザーバーです。「スナイパー」ネットワークエンジンを実装しており、ローカルファイルの
	スキャンとWeb APIのポーリングを組み合わせることで、認証済みのDNSクエリログをジッターの
	ないストリームとして提供します。

# オプション

## 一般オプション

*--config* <path>
	特定の設定JSONファイルを読み込みます。デフォルトは
	*~/.config/dns-stream/config.json* または */etc/dns-stream/config.json* です。

*--log-path* <path>
	ローカルの AdGuardHome *querylog.json* へのパスを指定します。

*--log-mode* <auto|force|disable>
	*auto*: ファイルをスキャンした後、APIモードへ切り替えます。
	*force*: ローカルファイルのみを読み取り、終了します。
	*disable*: ファイルスキャンをスキップし、APIポーリングのみを使用します。

*--start* <timestamp>
	特定の時刻からストリーミングを開始します（RFC3339 曖昧形式、例: "2026-01-01"）。

*--end* <timestamp>
	特定の時刻に達した時点でストリームを終了します。

*--polling* <seconds>
	APIポーリングの間隔を指定します（デフォルト: 1.0）。

*--limit* <number>
	1回のAPIリクエストで取得するエントリ数（デフォルト: 500、最大: 5000）。

*--max-seen* <number>
	ログエントリの重複を防止するための重複排除バッファのサイズ（デフォルト: 64）。

*--no-color*
	ANSIカラー出力を無効にします。

## 認証オプション

*--url* <url>
	DNSサーバーのベースURL（例: <http://127.0.0.1:80>）。

*--user* <username>
	API認証用のユーザー名。

*--pass* <password>
	平文のパスワード（非推奨。*--vault* または環境変数の使用を推奨）。

*--vault* <path>
	GPG暗号化された *password-store* (pass) 内のエントリへのパス。

*--drop-user* <username>
	保護されたログファイルを開いた後、権限を割譲するユーザーを指定します（root実行時）。

## ネットワーク・プロキシオプション

*--proxy* <url>
	プロキシURL（例: *socks5://127.0.0.1:1080* または *<http://proxy:8118>*）。
	"none" を指定すると無効化されます。

*--insecure*
	TLS証明書の検証を無効にします。

*--network-probe*
	ネットワークマトリクス（DNS解決、プロキシ接続、TLS Snipe）をテストして終了します。

*--ip* <pattern...>
	クライアントIPでログをフィルタリングします。ワイルドカード（例: *192.168.1.*）をサポート。

*--name* <string...>
	クライアント名またはドメイン名でログをフィルタリングします。

## デバッグオプション

*--debug*
	一般的なデバッグログを有効にします。

*--debug-mem*
	ターミナルのフッターにリアルタイムのメモリ使用統計を表示します。

*--debug-ansi*
	デバッグ出力に生のANSIエスケープシーケンスを表示します。

# 設定 (JSON)

設定ファイルはフラグと同様のロジックに従います。主要なキーと値：

*api_url* (string|array)
	DNSサーバーのURL。

*colors* (object)
	IPパターンをANSIカラー名にマッピングします。
	例: *{"192.168.\*": "blue", "127.0.0.1": "gray"}*
	サポートされる色: *red, green, yellow, blue, magenta, cyan, gray, dim, bold*。

*time_offset* (integer)
	サーバーのタイムスタンプからのオフセット秒数。

# 環境変数

*AGH_URL*
	API URLを上書きします。

*AGH_USER*
	認証ユーザー名を上書きします。

*AGH_PASS*
	認証パスワードを上書きします。

*AGH_VAULT*
	password-store のエントリパスを上書きします。

*AGH_START* / *AGH_END*
	開始/終了時刻フィルタを上書きします。

*PASSWORD_STORE_DIR*
	GPGパスワードストアのカスタムパス。

# ファイル

*/etc/dns-stream/config.json*
	システム全体の設定ファイル。

*~/.config/dns-stream/config.json*
	ユーザ固有の設定ファイル。

# 実行例

GPG認証を使用してローカルの AdGuardHome インスタンスを監視：
	*dns-stream --vault "services/agh" --log-mode auto*

リモートインスタンスへの SOCKS5 プロキシ接続をテスト：
	*dns-stream --url <https://remote-dns.lan> --proxy socks5://127.0.0.1:1080 --network-probe*

特定のサブネットをフィルタリングし、メモリ監視を有効にして実行：
	*dns-stream --ip "10.0.0.\*" --debug-mem*

# 著者

TSUKUMO Akito <tsukumoakito99@duck.com>

# ライセンス

MIT ライセンス
