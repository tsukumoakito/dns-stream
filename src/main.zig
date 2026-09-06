const std = @import("std");
const c_std = std.c;
const posix = std.posix;
const system = posix.system;
const Io = std.Io;
const Uri = std.Uri;
const mem = std.mem;
const fmt = std.fmt;
const http = std.http;
const heap = std.heap;
const debug = std.debug;
const builtin = std.builtin;
const process = std.process;
const File = Io.File;
const Clock = Io.Clock;
const Group = Io.Group;
const Terminal = Io.Terminal;
const Client = http.Client;
const Alignment = mem.Alignment;
const FixedBufferAllocator = heap.FixedBufferAllocator;

const root = @import("dns_stream");
const Stream = root.Stream;
const Crypt = root.Crypt;
const Store = root.Store;
const Auth = root.Auth;
const Config = root.Config;
const Engine = root.Engine;
const Network = root.Network;
const Session = root.Session;
const Format = root.Format;
const LogLine = root.LogLine;
const Summary = root.Summary;
pub const Diagnostic = root.Diagnostic;
const RuntimeSupport = root.RuntimeSupport;

const probe_tool = @import("probe_tool.zig");

pub var use_custom_panic: bool = false;

pub fn panic(msg: []const u8, stack_trace: ?*builtin.StackTrace, ret_addr: ?usize) noreturn {
    if (use_custom_panic) {
        RuntimeSupport.handlePanic(msg, stack_trace, ret_addr, Store);
    }

    debug.defaultPanic(msg, ret_addr);
}

const DiagContext = RuntimeSupport.getDiagContext();

var persistent_storage: [512 * 1024]u8 align(16) = undefined;

var g_io: Io = undefined;
var g_group: *Group = undefined;

fn sigHandler(_: posix.SIG) callconv(.c) void {
    Store.should_exit = true;
    g_group.cancel(g_io);
}

pub fn main(init: process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    var is_probe = false;
    var debug_enabled = false;

    var it_check = try init.minimal.args.iterateAllocator(arena);
    defer it_check.deinit();

    while (it_check.next()) |arg| {
        if (mem.eql(u8, arg, "--network-probe")) is_probe = true;
        if (mem.eql(u8, arg, "--debug")) debug_enabled = true;
    }

    if (is_probe) {
        try probe_tool.run(io, arena, debug_enabled);
        return;
    }

    var persistent_fba = FixedBufferAllocator.init(&persistent_storage);
    const base_allocator = persistent_fba.allocator();

    var it_config = try init.minimal.args.iterateAllocator(arena);
    defer it_config.deinit();

    var config = try Config.load(init.io, arena, &it_config, init.minimal.environ);

    const align_16 = comptime Alignment.fromByteUnits(16);
    const scratch_size = @max(@as(usize, config.api_limit) * root.JSON_ENTRY_SIZE_HINT, root.MIN_SCRATCH_SIZE);

    const dynamic_scratch = try arena.alignedAlloc(u8, align_16, scratch_size);
    const net_client_buf = try arena.alignedAlloc(u8, align_16, root.NET_CLIENT_BUF_SIZE);
    const net_req_buf = try arena.alignedAlloc(u8, align_16, root.NET_REQ_BUF_SIZE);

    var io_group = Group.init;
    defer io_group.cancel(io);

    g_io = io;
    g_group = &io_group;

    var act = posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };

    _ = posix.sigaction(posix.SIG.INT, &act, null);
    _ = posix.sigaction(posix.SIG.TERM, &act, null);

    var it_diag = try init.minimal.args.iterateAllocator(arena);
    defer it_diag.deinit();

    var diag = DiagContext.fromSystemArgs(&it_diag);
    defer diag.deinit(init.io);

    Store.init(io, base_allocator, dynamic_scratch, net_client_buf, net_req_buf, config.max_seen);
    Store.debug_mode = debug_enabled;

    Stream.syncDebugMode(diag.enabled, DiagContext.formatSizeBuf);
    defer Store.deinit(init.io);

    const env_map = try init.minimal.environ.createMap(arena);

    const sniper_io = Network.createSniperIo(io);

    const target_user_uid = blk: {
        if (init.minimal.environ.getPosix("SUDO_USER")) |u| {
            var u_buf: [128]u8 = undefined;
            const u_z = try fmt.bufPrintZ(&u_buf, "{s}", .{u});
            if (c_std.getpwnam(u_z.ptr)) |pw| {
                const p: *align(1) const c_std.passwd = @ptrCast(pw);
                break :blk p.uid;
            }
        }

        if (config.drop_user) |du| {
            const drop_z = try arena.dupeZ(u8, du);
            if (c_std.getpwnam(drop_z.ptr)) |pw| {
                const p: *align(1) const c_std.passwd = @ptrCast(pw);
                break :blk p.uid;
            }
        }

        break :blk system.getuid();
    };

    const winner_base_url = blk: {
        const target_list = if (config.api_urls.len > 0) config.api_urls else @constCast(&[_][]const u8{config.api_url});
        const reachable = Engine.findFirstReachableUrl(sniper_io, target_list) catch |err| {
            if (err == error.OperationAborted) return;

            debug.print("\n\x1b[91m[ERROR]\x1b[0m Failed to reach any valid API endpoint.\n", .{});
            debug.print("\x1b[93m[HINT]\x1b[0m Please verify the following:\n", .{});
            debug.print("  - Is the server address or port correct?\n", .{});
            debug.print("  - Is the network or VPN connection active?\n", .{});
            debug.print("  - Is the proxy configuration (if any) accurate?\n", .{});
            debug.print("  - If using HTTPS, does the server respond to TLS handshakes?\n", .{});
            debug.print("\n\x1b[90m(Technical details: {any})\x1b[0m\n", .{err});
            return;
        };

        break :blk reachable;
    };

    var url_full_buf: [512]u8 = undefined;
    const final_url = if (mem.indexOf(u8, winner_base_url, "/control") == null) blk: {
        const suffix = if (mem.endsWith(u8, winner_base_url, "/")) "control" else "/control";
        break :blk try fmt.bufPrint(&url_full_buf, "{s}{s}", .{ winner_base_url, suffix });
    } else winner_base_url;

    if (Store.dns_resolve_len == 0) {
        try Engine.resolveTargetIp(sniper_io, final_url);
    }

    var http_client = Client{
        .allocator = Store.net_client_fba.allocator(),
        .io = sniper_io,
        .ca_bundle = .empty,
        .now = Clock.real.now(sniper_io),
    };

    defer {
        http_client.ca_bundle.deinit(base_allocator);
        http_client.ca_bundle = .empty;
        http_client.deinit();

        Crypt.GpgDecrypter.removeFromKeyring(Store.keyring_key_name) catch {};
    }

    try http_client.initDefaultProxies(arena, &env_map);

    if (config.proxy) |p| {
        if (!mem.eql(u8, p, "none")) {
            const p_uri = try Uri.parse(p);
            const scheme = p_uri.scheme;
            var ph_buf: [Io.net.HostName.max_len]u8 = undefined;
            const p_host = try p_uri.getHost(&ph_buf);
            const is_socks = mem.startsWith(u8, scheme, "socks5");
            const is_https_proxy = mem.eql(u8, scheme, "https");

            Store.proxy_type = if (is_socks) .socks5 else if (is_https_proxy) .https else .http;
            const p_len = @min(p.len, Store.proxy_url.len);
            @memcpy(Store.proxy_url[0..p_len], p[0..p_len]);
            Store.proxy_url_len = p_len;

            if (!is_socks) {
                const proxy_ptr = try arena.create(http.Client.Proxy);
                proxy_ptr.* = .{
                    .protocol = if (is_https_proxy) .tls else .plain,
                    .host = .{ .bytes = try arena.dupe(u8, p_host.bytes) },
                    .port = p_uri.port orelse 8080,
                    .authorization = null,
                    .supports_connect = true,
                };

                http_client.http_proxy = proxy_ptr;
                http_client.https_proxy = proxy_ptr;
            }

            if (Store.debug_mode) {
                debug.print("\x1b[90m[DEBUG]\x1b[0m Proxy Configuration (Override): Type={s}, URL={s}\n", .{ @tagName(Store.proxy_type), Store.proxy_url[0..Store.proxy_url_len] });
            }
        } else {
            Store.proxy_type = .none;
            Store.proxy_url_len = 0;
            http_client.http_proxy = null;
            http_client.https_proxy = null;
        }
    }

    if (!config.insecure) {
        try http_client.ca_bundle.rescan(base_allocator, sniper_io, Clock.real.now(sniper_io));
    }

    var login_url_buf: [512]u8 = undefined;
    const login_endpoint = try fmt.bufPrint(&login_url_buf, "{s}/login", .{final_url});

    const stdout_file = File.stdout();
    const terminal_mode = try Terminal.Mode.detect(io, stdout_file, config.no_color, false);
    var stdout_writer_wrapper = stdout_file.writer(io, &.{});
    var terminal_obj = Terminal{ .writer = &stdout_writer_wrapper.interface, .mode = terminal_mode };

    Auth.ensureAuthenticated(
        &terminal_obj,
        sniper_io,
        base_allocator,
        arena,
        &http_client,
        &config,
        login_endpoint,
        init.minimal.environ,
    ) catch |err| {
        if (err == error.OperationAborted or Store.should_exit) {
            try stdout_file.writeStreamingAll(sniper_io, "\n" ++ Format.clr_yellow ++ "👋 Monitoring cancelled by user." ++ Format.clr_reset ++ "\n");
            return;
        }

        return err;
    };

    if (Store.should_exit) return;

    {
        var clients_url_buf: [512]u8 = undefined;
        const clients_endpoint = try fmt.bufPrint(&clients_url_buf, "{s}/clients", .{final_url});
        try Engine.fetchClientMap(base_allocator, &http_client, clients_endpoint);
    }

    const sess = try Session.initialize(sniper_io, arena, &http_client, &config, final_url);

    try Summary.print(&terminal_obj, sniper_io, config, final_url, sess.session_start, sess.effective_start);

    const initial_winsize = Stream.getTermSize();
    try LogLine.printHeader(sniper_io, stdout_file, initial_winsize.col, config.no_color);

    const polling_ms = @as(u64, @trunc(config.polling_s * 1000.0));

    try Stream.start(
        &io_group,
        base_allocator,
        &http_client,
        final_url,
        sess.effective_start,
        target_user_uid,
        config.log_path,
        config.user,
        diag,
        config.log_mode,
        config.scan_limit_mb,
        polling_ms,
        config.api_limit,
        config.no_color,
        config.catchup_limit,
        &config,
        init.minimal.environ,
    );

    try io_group.await(io);

    try stdout_file.writeStreamingAll(sniper_io, "\n" ++ Format.clr_bold ++ "Monitoring session concluded." ++ Format.clr_reset ++ "\n");

    process.cleanExit(io);
}
