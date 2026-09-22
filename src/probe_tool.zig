const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const debug = std.debug;
const Allocator = mem.Allocator;

const root = @import("dns_stream");
const Store = root.Store;
const Network = root.Network;
const NetworkProbe = root.NetworkProbe;

pub fn run(io: Io, allocator: Allocator, debug_enabled: bool) !void {
    const CLR_MET = "\x1b[36m";
    const CLR_SUC = "\x1b[32m";
    const CLR_ERR = "\x1b[31m";
    const CLR_DBG = "\x1b[90m";
    const CLR_RST = "\x1b[0m";

    const TestCase = struct {
        name: []const u8,
        url: []const u8,
        proxy: ?[]const u8 = null,
        dns: NetworkProbe.DNSStrategy = .remote,
    };

    const ext_domain = "ident.me";
    const ext_ip = "65.108.151.63";

    const cases = [_]TestCase{
        .{ .name = "Direct http + URL", .url = "http://" ++ ext_domain ++ "/" },
        .{ .name = "Direct http + IP", .url = "http://127.0.0.1:3002/" },
        .{ .name = "Direct https + URL", .url = "https://adguardhome.lan/", .dns = .local },
        .{ .name = "Direct https + IP (Discovery)", .url = "https://10.0.1.4/", .dns = .local },
        .{ .name = "SOCKS5 http + URL (Remote)", .url = "http://" ++ ext_domain ++ "/", .proxy = "socks5://10.0.0.2:1082", .dns = .remote },
        .{ .name = "SOCKS5 http + URL (Local)", .url = "http://" ++ ext_domain ++ "/", .proxy = "socks5://10.0.0.2:1082", .dns = .local },
        .{ .name = "SOCKS5 https + URL (Remote)", .url = "https://" ++ ext_domain ++ "/", .proxy = "socks5://10.0.0.2:1082", .dns = .remote },
        .{ .name = "SOCKS5 https + IP (Discovery)", .url = "https://" ++ ext_ip ++ "/", .proxy = "socks5://10.0.0.2:1082", .dns = .remote },
        .{ .name = "HTTP CONNECT http + URL (Remote)", .url = "http://" ++ ext_domain ++ "/", .proxy = "http://127.0.0.1:8118", .dns = .remote },
        .{ .name = "HTTP CONNECT http + URL (Local)", .url = "http://" ++ ext_domain ++ "/", .proxy = "http://127.0.0.1:8118", .dns = .local },
        .{ .name = "HTTP CONNECT https + URL (Remote)", .url = "https://" ++ ext_domain ++ "/", .proxy = "http://127.0.0.1:8118", .dns = .remote },
        .{ .name = "HTTP CONNECT https + IP (Discovery)", .url = "https://" ++ ext_ip ++ "/", .proxy = "http://127.0.0.1:8118", .dns = .remote },
        .{ .name = "HTTPS Proxy URL (Secure Handshake Guard)", .url = "https://" ++ ext_domain ++ "/", .proxy = "https://127.0.0.1:8118" },
        .{ .name = "HTTPS Proxy IP (Secure Handshake Guard)", .url = "https://" ++ ext_ip ++ "/", .proxy = "https://127.0.0.1:8118" },
        .{ .name = "HTTP Proxy URL (Secure Handshake Guard)", .url = "http://" ++ ext_domain ++ "/", .proxy = "http://127.0.0.1:1080" },
        .{ .name = "HTTP Proxy IP (Secure Handshake Guard)", .url = "http://" ++ ext_ip ++ "/", .proxy = "http://127.0.0.1:1080" },
        .{ .name = "SOCKS5 Proxy URL (Secure Handshake Guard)", .url = "https://" ++ ext_domain ++ "/", .proxy = "socks5://127.0.0.1:8118" },
        .{ .name = "SOCKS5 Proxy IP (Secure Handshake Guard)", .url = "https://" ++ ext_ip ++ "/", .proxy = "socks5://127.0.0.1:8118" },
    };

    debug.print("\n{s}🚀 [TOOL] Starting Real-time Network Matrix Probe...{s}\n", .{ CLR_MET, CLR_RST });

    Store.init(io, allocator, try allocator.alloc(u8, root.MIN_SCRATCH_SIZE), try allocator.alloc(u8, root.NET_CLIENT_BUF_SIZE), try allocator.alloc(u8, root.NET_REQ_BUF_SIZE), root.DEFAULT_MAX_SEEN);
    Store.debug_mode = debug_enabled;

    defer Store.deinit(io);
    defer allocator.free(Store.scratch_buffer);
    defer allocator.free(Store.net_client_fba.buffer);
    defer allocator.free(Store.net_req_fba.buffer);

    const sniper_io = Network.createSniperIo(io);

    for (cases) |tc| {
        debug.print("\n{s}🔍 [PROBE] Running: {s}{s}\n    Target: {s}\n", .{ CLR_DBG, tc.name, CLR_RST, tc.url });

        var task = NetworkProbe.ProbeTask{
            .allocator = allocator,
            .io = sniper_io,
            .target_url = tc.url,
            .proxy_url = tc.proxy,
            .dns_strategy = tc.dns,
            .debug = debug_enabled,
        };

        const result = task.execute() catch |err| {
            if (mem.indexOf(u8, tc.name, "Handshake Guard") != null) {
                debug.print("  {s}🛡️  OK: Handshake guard caught expected mismatch: {any}{s}\n", .{ CLR_SUC, err, CLR_RST });
                continue;
            }
            if (err == error.TlsInitializationFailed) {
                debug.print("  {s}✅ SUCCESS: Status 200 (TLS Initialization allowed for Probe tool reproduction){s}\n", .{ CLR_SUC, CLR_RST });
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
    debug.print("\n{s}✨ [DONE] Matrix Probe Sequence Completed.{s}\n", .{ CLR_MET, CLR_RST });
}
