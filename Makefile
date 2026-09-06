# dns-stream Makefile
# SPDX-FileCopyrightText: 2026 TSUKUMO Akito <tsukumoakito99@duck.com>
# SPDX-License-Identifier: MIT

ZIG_VER    ?= 0.16.0
PREFIX     ?= /usr
CONFDIR    ?= /etc/dns-stream
BINDIR      = $(DESTDIR)$(PREFIX)/bin
MANDIR      = $(DESTDIR)$(PREFIX)/share/man
DOCDIR      = $(DESTDIR)$(PREFIX)/share/doc/dns-stream
LICENSEDIR  = $(DESTDIR)$(PREFIX)/share/licenses/dns-stream
ETCDIR      = $(DESTDIR)$(CONFDIR)

.PHONY: all build check-zig install uninstall clean

all: build

check-zig:
	@ZIG_CURRENT=$$(zig version 2>/dev/null || echo "none"); \
	case $$ZIG_CURRENT in \
		$(ZIG_VER)*) \
			echo "✅ Zig version $$ZIG_CURRENT detected."; \
			;; \
		*) \
			echo "⚠️  Zig version mismatch (Current: $$ZIG_CURRENT, Required: $(ZIG_VER))."; \
			if command -v zvm >/dev/null 2>&1; then \
				echo "🔄 zvm detected. Attempting to switch to $(ZIG_VER)..."; \
				zvm use $(ZIG_VER) >/dev/null 2>&1 || true; \
				ZIG_NEW=$$(zig version 2>/dev/null || echo "none"); \
				case $$ZIG_NEW in \
					$(ZIG_VER)*) \
						echo "✅ Successfully switched to Zig $$ZIG_NEW."; \
						;; \
					*) \
						echo "❌ Error: zvm failed to switch to Zig $(ZIG_VER)."; \
						exit 1; \
						;; \
				esac; \
			else \
				echo "❌ Error: Current version requires Zig $(ZIG_VER)."; \
				echo "   zvm not found. Please install Zig $(ZIG_VER) manually."; \
				exit 1; \
			fi; \
			;; \
	esac

build: check-zig
	zig build -Doptimize=ReleaseSafe

install:
	install -Dm755 zig-out/bin/dns-stream "$(BINDIR)/dns-stream"

	install -d "$(ETCDIR)"
	@if [ -f "$(ETCDIR)/config.json" ]; then \
		echo "⚠️  Existing config.json found. Installing as config.json.example"; \
		install -m644 config.json "$(ETCDIR)/config.json.example"; \
	else \
		install -m644 config.json "$(ETCDIR)/config.json"; \
	fi

	install -Dm644 zig-out/share/man/man1/dns-stream.1 "$(MANDIR)/man1/dns-stream.1"
	install -Dm644 zig-out/share/man/ja/man1/dns-stream.1 "$(MANDIR)/ja/man1/dns-stream.1"
	install -Dm644 zig-out/doc/MANUAL.md "$(DOCDIR)/MANUAL.md"
	install -Dm644 zig-out/doc/MANUAL_ja.md "$(DOCDIR)/MANUAL_ja.md"
	install -Dm644 README.md "$(DOCDIR)/README.md"
	install -Dm644 README_ja.md "$(DOCDIR)/README_ja.md"
	install -Dm644 LICENSE "$(LICENSEDIR)/LICENSE"

uninstall:
	rm -f "$(BINDIR)/dns-stream"
	rm -f "$(MANDIR)/man1/dns-stream.1"
	rm -f "$(MANDIR)/ja/man1/dns-stream.1"
	rm -rf "$(DOCDIR)"
	rm -rf "$(LICENSEDIR)"
	@echo "ℹ️  Note: $(ETCDIR) was preserved to protect your configuration."
	@echo "   To remove it manually, run: sudo rm -rf $(ETCDIR)"

clean:
	rm -rf zig-out .zig-cache
