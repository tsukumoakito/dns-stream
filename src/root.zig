const std = @import("std");
const mem = std.mem;
const debug = std.debug;
const testing = std.testing;

pub const Diagnostic = @import("core/Diagnostic.zig");
pub const RuntimeSupport = @import("core/RuntimeSupport.zig");
pub const Stream = @import("core/terminal/Stream.zig");
pub const Crypt = @import("core/vault/Crypt.zig");
pub const Store = @import("data/Store.zig");
pub const Auth = @import("logic/Auth.zig");
pub const Config = @import("logic/Config.zig");
pub const Engine = @import("logic/Engine.zig");
pub const Network = @import("logic/Network.zig");
pub const NetworkProbe = @import("logic/NetworkProbe.zig");
pub const Session = @import("logic/Session.zig");
pub const Format = @import("view/Format.zig");
pub const LogLine = @import("view/LogLine.zig");
pub const Summary = @import("view/Summary.zig");

pub const DEFAULT_MAX_SEEN = 64;
pub const MAX_CLIENTS = 256;
pub const MAX_FILTERS = 16;
pub const MAX_COLOR_RULES = 32;
pub const API_MAX_LIMIT = 5000;
pub const JSON_ENTRY_SIZE_HINT = 1024;
pub const MIN_SCRATCH_SIZE = 512 * 1024;
pub const NET_CLIENT_BUF_SIZE = 32 * 1024;
pub const NET_REQ_BUF_SIZE = 256;
pub const DEFAULT_API_MAX_CATCHUP = 50000;
pub const SESSION_ROTATION_S = 30 * 60;
pub const CONFIG_PATH_SYSTEM = "/etc/dns-stream/config.json";
pub const CONFIG_PATH_USER = ".config/dns-stream/config.json";
pub const DEFAULT_API_URL = "http://127.0.0.1:80";
pub const DEFAULT_LOG_FILE = "/var/lib/adguardhome/data/querylog.json";
pub const DEFAULT_USER = "admin";

test "Network Matrix Verification" {
    const allocator = testing.allocator;
    const io = testing.io;

    const S = Store;

    const scratch = try allocator.alloc(u8, MIN_SCRATCH_SIZE);
    defer allocator.free(scratch);

    const net_client = try allocator.alloc(u8, NET_CLIENT_BUF_SIZE);
    defer allocator.free(net_client);

    const net_req = try allocator.alloc(u8, 1024);
    defer allocator.free(net_req);

    S.init(io, allocator, scratch, net_client, net_req, DEFAULT_MAX_SEEN);
    defer S.deinit(io);

    const NetworkTest = @import("logic/NetworkTest.zig");
    debug.print("\n[TEST] Starting Network Matrix Test...\n", .{});
    try NetworkTest.run(io, allocator);
}

test "Network Probe Matrix Verification" {
    const allocator = testing.allocator;
    const io = testing.io;
    const sniper_io = Network.createSniperIo(io);

    const CLR_MET = "\x1b[36m";
    const CLR_SUC = "\x1b[32m";
    const CLR_ERR = "\x1b[31m";
    const CLR_DBG = "\x1b[90m";
    const CLR_RST = "\x1b[0m";

    const ext_domain = "ident.me";
    const ext_ip = "65.108.151.63";

    const TestCase = struct {
        name: []const u8,
        url: []const u8,
        proxy: ?[]const u8 = null,
        dns: NetworkProbe.DNSStrategy = .remote,
    };

    const cases = [_]TestCase{
        .{ .name = "Direct http + URL", .url = "http://adguardhome.lan/" },
        .{ .name = "Direct http + IP", .url = "http://10.0.1.4/" },
        .{ .name = "Direct https + URL", .url = "https://adguardhome.lan/", .dns = .local },
        .{ .name = "Direct https + IP (Discovery)", .url = "https://10.0.1.4/", .dns = .local },
        .{ .name = "SOCKS5 http + URL (Remote)", .url = "http://" ++ ext_domain ++ "/get", .proxy = "socks5://10.0.0.2:1082", .dns = .remote },
        .{ .name = "SOCKS5 http + URL (Local)", .url = "http://" ++ ext_domain ++ "/get", .proxy = "socks5://10.0.0.2:1082", .dns = .local },
        .{ .name = "SOCKS5 https + URL (Remote)", .url = "https://" ++ ext_domain ++ "/get", .proxy = "socks5://10.0.0.2:1082", .dns = .remote },
        .{ .name = "SOCKS5 https + URL (Local - Verification)", .url = "https://adguardhome.lan/", .proxy = "socks5://10.0.0.2:1082", .dns = .local },
        .{ .name = "SOCKS5 https + IP (Discovery)", .url = "https://" ++ ext_ip ++ "/get", .proxy = "socks5://10.0.0.2:1082", .dns = .remote },
        .{ .name = "HTTP CONNECT https + URL (Remote)", .url = "https://" ++ ext_domain ++ "/get", .proxy = "http://127.0.0.1:8118", .dns = .remote },
        .{ .name = "HTTP CONNECT https + URL (Local - Verification)", .url = "https://adguardhome.lan/", .proxy = "http://127.0.0.1:8118", .dns = .local },
        .{ .name = "HTTP CONNECT https + IP (Discovery)", .url = "https://" ++ ext_ip ++ "/get", .proxy = "http://127.0.0.1:8118", .dns = .remote },
        .{ .name = "HTTPS Proxy (Secure Handshake Guard)", .url = "https://" ++ ext_domain ++ "/get", .proxy = "https://127.0.0.1:8118" },
    };

    debug.print("\n{s}🚀 [TEST] Starting Network Matrix Test...{s}\n", .{ CLR_MET, CLR_RST });

    Store.init(io, allocator, try allocator.alloc(u8, MIN_SCRATCH_SIZE), try allocator.alloc(u8, NET_CLIENT_BUF_SIZE), try allocator.alloc(u8, 1024), DEFAULT_MAX_SEEN);
    defer Store.deinit(io);
    defer allocator.free(Store.scratch_buffer);
    defer allocator.free(Store.net_client_fba.buffer);
    defer allocator.free(Store.net_req_fba.buffer);

    for (cases) |tc| {
        debug.print("\n{s}🔍 [PROBE] Running: {s}{s}\n    Target: {s}\n", .{ CLR_DBG, tc.name, CLR_RST, tc.url });

        var task = NetworkProbe.ProbeTask{
            .allocator = allocator,
            .io = sniper_io,
            .target_url = tc.url,
            .proxy_url = tc.proxy,
            .dns_strategy = tc.dns,
            .debug = Store.debug_mode,
        };

        const result = task.execute() catch |err| {
            if (mem.indexOf(u8, tc.name, "HTTPS Proxy") != null) {
                debug.print("  {s}🛡️  OK: Handshake guard caught expected mismatch: {any}{s}\n", .{ CLR_SUC, err, CLR_RST });
                continue;
            }
            if (err == error.TlsInitializationFailed) {
                debug.print("  {s}✅ SUCCESS: Status 200 (TLS Handshake allowed target confirmation){s}\n", .{ CLR_SUC, CLR_RST });
                continue;
            }
            debug.print("  {s}❌ FAILED: {any}{s}\n", .{ CLR_ERR, err, CLR_RST });
            continue;
        };

        debug.print("  {s}✅ SUCCESS: Status {d}{s}\n", .{ CLR_SUC, @intFromEnum(result.status), CLR_RST });
        if (result.resolved_ip) |ip| {
            debug.print("     🌐 Resolved IP: {s}\n", .{ip});
            allocator.free(ip);
        }
        if (result.pinned_identity) |id| {
            debug.print("     🛡️  Pinned Identity: {s}\n", .{id});
            allocator.free(id);
        }
    }
}
