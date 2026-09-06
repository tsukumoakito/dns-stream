dns-stream(1) "1.0.2" "dns-stream User Manual"

# NAME

dns-stream - Unified real-time DNS log stream and visualization engine

# SYNOPSIS

*dns-stream* [OPTIONS...]

# DESCRIPTION

*dns-stream* is a high-performance terminal observer for AdGuardHome (and future DNS
engines). It implements a "Sniper" network engine to provide a jitter-free,
authenticated stream of DNS query logs by combining local file scanning and
Web API polling.

# OPTIONS

## General Options

*--config* <path>
	Load configuration from a specific JSON file. Defaults to
	*~/.config/dns-stream/config.json* or */etc/dns-stream/config.json*.

*--log-path* <path>
	Path to the local AdGuardHome *querylog.json*.

*--log-mode* <auto|force|disable>
	*auto*: Scan file then switch to API.
	*force*: Only read from the local file and exit.
	*disable*: Skip file scanning and use API polling only.

*--start* <timestamp>
	Start streaming from a specific time (RFC3339 fuzzy format, e.g., "2026-01-01").

*--end* <timestamp>
	Terminate the stream once a specific time is reached.

*--polling* <seconds>
	Interval for API polling (default: 1.0).

*--limit* <number>
	Number of entries to fetch per API request (default: 500, max: 5000).

*--max-seen* <number>
	Size of the deduplication buffer to prevent duplicate log entries (default: 64).

*--no-color*
	Disable ANSI color output.

## Authentication Options

*--url* <url>
	The base URL of the DNS server (e.g., <http://127.0.0.1:80>).

*--user* <username>
	Username for API authentication.

*--pass* <password>
	Plaintext password (not recommended, use *--vault* or environment variables).

*--vault* <path>
	Path to an entry in the GPG-encrypted *password-store* (pass).

*--drop-user* <username>
	User to drop privileges to after opening protected log files.

## Network and Proxy Options

*--proxy* <url>
	Proxy URL (e.g., *socks5://127.0.0.1:1080* or *<http://proxy:8118>*).
	Set to "none" to disable.

*--insecure*
	Disable TLS certificate verification.

*--network-probe*
	Test the network matrix (DNS resolution, Proxy connectivity, and TLS Snipe) and exit.

*--ip* <pattern...>
	Filter logs by client IP. Supports wildcards (e.g., *192.168.1.*).

*--name* <string...>
	Filter logs by client name or domain.

## Debug Options

*--debug*
	Enable general debug logging.

*--debug-mem*
	Show real-time memory usage statistics in the terminal footer.

*--debug-ansi*
	Show raw ANSI escape sequences in debug output.

# CONFIGURATION (JSON)

The configuration file follows the same logic as the flags. Key-value pairs:

*api_url* (string|array)
	The URL(s) of the DNS server.

*colors* (object)
	Map IP patterns to ANSI color names.
	Example: *{"192.168.\*": "blue", "127.0.0.1": "gray"}*
	Supported colors: *red, green, yellow, blue, magenta, cyan, gray, dim, bold*.

*time_offset* (integer)
	Seconds to offset from the server's timestamp.

# ENVIRONMENT

*AGH_URL*
	Override the API URL.

*AGH_USER*
	Override the authentication user.

*AGH_PASS*
	Override the authentication password.

*AGH_VAULT*
	Path to the password-store entry.

*AGH_START* / *AGH_END*
	Override start/end time filters.

*PASSWORD_STORE_DIR*
	Custom path to the GPG password store.

# FILES

*/etc/dns-stream/config.json*
	System-wide configuration.

*~/.config/dns-stream/config.json*
	User-specific configuration.

# EXAMPLES

Stream from a local AGH instance with GPG authentication:
	*dns-stream --vault "services/agh" --log-mode auto*

Test a SOCKS5 proxy connection to a remote instance:
	*dns-stream --url <https://remote-dns.lan> --proxy socks5://127.0.0.1:1080 --network-probe*

Filter logs for a specific subnet with memory monitoring:
	*dns-stream --ip "10.0.0.\*" --debug-mem*

# AUTHORS

TSUKUMO Akito <tsukumoakito99@duck.com>

# LICENSE

MIT License
