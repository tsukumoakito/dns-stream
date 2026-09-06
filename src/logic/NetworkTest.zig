const std = @import("std");
const Io = std.Io;
const Uri = std.Uri;
const mem = std.mem;
const fmt = std.fmt;
const debug = std.debug;
const Duration = Io.Duration;
const HostName = Io.net.HostName;
const Select = Io.Select;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

const Store = @import("../data/Store.zig");
const Engine = @import("Engine.zig");
const Network = @import("Network.zig");
const NetworkProbe = @import("NetworkProbe.zig");

const CLR_DBG = "\x1b[90m";
const CLR_SUC = "\x1b[32m";
const CLR_ERR = "\x1b[31m";
const CLR_MET = "\x1b[36m";
const CLR_RST = "\x1b[0m";

const TestCase = struct {
    name: []const u8,
    target_url: []const u8,
    proxy_url: ?[]const u8 = null,
    dns: NetworkProbe.DNSStrategy = .remote,
};

const ResultUnion = union(enum) {
    done: ?anyerror,
    timeout: void,
};

fn timerTask(io: Io, d: Duration) void {
    io.sleep(d, .awake) catch {};
}

fn wrapperTask(io: Io, allocator: Allocator, tc: TestCase) ?anyerror {
    processTestCase(io, allocator, tc) catch |err| return err;
    return null;
}

pub fn run(io: Io, allocator: Allocator) !void {
    const old_proxy_type = Store.proxy_type;
    var old_proxy_url: [512]u8 = undefined;
    @memcpy(&old_proxy_url, &Store.proxy_url);
    const old_proxy_url_len = Store.proxy_url_len;

    defer {
        Store.proxy_type = old_proxy_type;
        @memcpy(Store.proxy_url[0..old_proxy_url_len], old_proxy_url[0..old_proxy_url_len]);
        Store.proxy_url_len = old_proxy_url_len;
        Store.pinned_identity_len = 0;
        Store.dns_resolve_len = 0;
        Store.dns_resolve_host_len = 0;
        debug.print("{s}[INFO] Network state restored to original config.{s}\n", .{ CLR_MET, CLR_RST });
    }

    const ext_domain = "ident.me";
    const ext_ip = "65.108.151.63";

    // const ext_domain = "httpbin.org";
    // const ext_ip = "54.87.65.228";

    var tests: ArrayList(TestCase) = .empty;
    defer {
        for (tests.items) |tc| {
            if (tc.proxy_url != null) allocator.free(tc.name);
        }
        tests.deinit(allocator);
    }

    try tests.append(allocator, .{ .name = "Local Domain", .target_url = "https://adguardhome.lan/", .dns = .local });
    try tests.append(allocator, .{ .name = "Local IP (SNIPE)", .target_url = "https://10.0.1.4/", .dns = .local });
    try tests.append(allocator, .{ .name = "Local Port", .target_url = "http://127.0.0.1:3002/" });

    const proxies = [_]struct { n: []const u8, url: []const u8 }{
        .{ .n = "socks5", .url = "socks5://10.0.0.2:1082" },
        .{ .n = "http", .url = "http://127.0.0.1:8118" },
        .{ .n = "https", .url = "https://127.0.0.1:8118" },
    };

    for (proxies) |p| {
        const targets = [_]struct { n: []const u8, u: []const u8 }{
            .{ .n = "Ext Domain HTTP", .u = "http://" ++ ext_domain ++ "/get" },
            .{ .n = "Ext Domain HTTPS", .u = "https://" ++ ext_domain ++ "/get" },
            .{ .n = "Ext IP HTTP", .u = "http://" ++ ext_ip ++ "/get" },
            .{ .n = "Ext IP HTTPS", .u = "https://" ++ ext_ip ++ "/get" },
        };
        for (targets) |t| {
            const full_name = try fmt.allocPrint(allocator, "[{s}] {s}", .{ p.n, t.n });
            try tests.append(allocator, .{
                .name = full_name,
                .target_url = t.u,
                .proxy_url = p.url,
            });
        }
    }

    debug.print("\n" ++ ("=" ** 30) ++ " NETWORK MATRIX TEST START " ++ ("=" ** 30) ++ "\n", .{});

    var sel_buf: [2]ResultUnion = undefined;
    const timeout_duration = Duration.fromSeconds(10);

    for (tests.items, 0..) |tc, i| {
        debug.print("{s}▶ [{d:0>2}/{d:0>2}] TEST: {s}{s}\n", .{ CLR_MET, i + 1, tests.items.len, tc.name, CLR_RST });

        Store.pinned_identity_len = 0;
        Store.dns_resolve_len = 0;
        Store.dns_resolve_host_len = 0;

        const old_prot = io.swapCancelProtection(.unblocked);
        defer _ = io.swapCancelProtection(old_prot);

        var sel = Select(ResultUnion).init(io, &sel_buf);
        sel.async(.done, wrapperTask, .{ io, allocator, tc });
        sel.async(.timeout, timerTask, .{ io, timeout_duration });

        const res = sel.await() catch |err| {
            debug.print("  {s}❌ [FAILED] Select Await Error: {s}{s}\n", .{ CLR_ERR, @errorName(err), CLR_RST });
            sel.cancelDiscard();
            continue;
        };

        switch (res) {
            .done => |opt_err| {
                sel.cancelDiscard();
                if (opt_err) |err| {
                    if (err == error.TlsInitializationFailed) {
                        debug.print("  {s}✅ [PASSED] (TLS Handshake confirmed target alive){s}\n", .{ CLR_SUC, CLR_RST });
                    } else if (err == error.Canceled) {
                        debug.print("  {s}❌ [FAILED] Test Timed Out (Limit Exceeded during DNS or Connect){s}\n", .{ CLR_ERR, CLR_RST });
                    } else if (err == error.ConnectionTimedOut or err == error.Timeout or err == error.HostNotFound) {
                        debug.print("  {s}❌ [FAILED] Network Error: {s}{s}\n", .{ CLR_ERR, @errorName(err), CLR_RST });
                    } else {
                        debug.print("  {s}❌ [FAILED] {s}{s}\n", .{ CLR_ERR, @errorName(err), CLR_RST });
                    }
                } else {
                    debug.print("  {s}✅ [PASSED]{s}\n", .{ CLR_SUC, CLR_RST });
                }
            },
            .timeout => {
                debug.print("  {s}❌ [FAILED] Test Timed Out (Global Timeout){s}\n", .{ CLR_ERR, CLR_RST });
                sel.cancelDiscard();
            },
        }
    }
    debug.print("=" ** 87 ++ "\n\n", .{});
}

fn processTestCase(io: Io, allocator: Allocator, tc: TestCase) !void {
    const sniper_io = Network.createSniperIo(io);

    var task = NetworkProbe.ProbeTask{
        .allocator = allocator,
        .io = sniper_io,
        .target_url = tc.target_url,
        .proxy_url = tc.proxy_url,
        .dns_strategy = tc.dns,
        .debug = Store.debug_mode,
    };

    const result = try task.execute();

    if (result.pinned_identity) |id| {
        const safe_len = @min(id.len, Store.pinned_identity.len);
        @memcpy(Store.pinned_identity[0..safe_len], id[0..safe_len]);
        Store.pinned_identity_len = safe_len;
        allocator.free(id);
    }

    if (result.resolved_ip) |ip| {
        const uri = try Uri.parse(tc.target_url);
        var h_buf: [HostName.max_len]u8 = undefined;
        const hostname = try uri.getHost(&h_buf);

        const dns_host_res = try fmt.bufPrintZ(&Store.dns_resolve_host, "{s}", .{hostname.bytes});
        Store.dns_resolve_host_len = dns_host_res.len;

        const dns_msg = try fmt.bufPrintZ(&Store.dns_resolve_str, "{s}", .{ip});
        Store.dns_resolve_len = dns_msg.len;
        allocator.free(ip);
    }

    if (@intFromEnum(result.status) >= 400) {
        debug.print("  {s}⚠  Status: {d}{s}\n", .{ CLR_DBG, @intFromEnum(result.status), CLR_RST });
    }
}
