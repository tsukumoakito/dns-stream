const std = @import("std");
const Io = std.Io;
const Uri = std.Uri;
const mem = std.mem;
const fmt = std.fmt;
const http = std.http;
const debug = std.debug;
const ascii = std.ascii;
const crypto = std.crypto;
const compress = std.compress;
const HostName = Io.net.HostName;
const Client = http.Client;
const Header = http.Header;
const Proxy = http.Client.Proxy;
const Connection = http.Client.Connection;
const Decompress = compress.flate.Decompress;
const Allocator = mem.Allocator;

const Store = @import("../../data/Store.zig");
const Network = @import("../Network.zig");

var gzip_window: [compress.flate.max_window_len]u8 align(16) = undefined;

pub fn getPinnedConnection(client: *Client, uri: Uri) !*Connection {
    const port = uri.port orelse (if (mem.eql(u8, uri.scheme, "https")) @as(u16, 443) else @as(u16, 80));
    const is_https = mem.eql(u8, uri.scheme, "https");
    var h_buf: [HostName.max_len]u8 = undefined;
    const hostname = try uri.getHost(&h_buf);
    const identity = if (Store.pinned_identity_len > 0)
        Store.pinned_identity[0..Store.pinned_identity_len]
    else
        hostname.bytes;

    const protocol: http.Client.Protocol = if (is_https) .tls else .plain;

    if (Store.proxy_type != .none) {
        const p_uri = try Uri.parse(Store.proxy_url[0..Store.proxy_url_len]);
        var ph_buf: [HostName.max_len]u8 = undefined;
        const p_host = (try p_uri.getHost(&ph_buf)).bytes;
        const p_port = p_uri.port orelse 8080;

        if (Store.proxy_type == .socks5) {
            var socks_ctx = Store.SocksContext{
                .proxy_host = p_host,
                .proxy_port = p_port,
                .target_ip = if (Store.dns_resolve_len > 0) Store.dns_resolve_str[0..Store.dns_resolve_len] else identity,
                .target_port = port,
            };
            Store.tls_socks_ctx = &socks_ctx;

            if (Store.debug_mode) {
                debug.print("\x1b[90m[DEBUG]\x1b[0m Connection pool lookup for SOCKS5: {s}:{d}\n", .{ hostname.bytes, p_port });
            }

            return try client.connect(HostName{ .bytes = identity }, port, protocol);
        } else if (Store.proxy_type == .http and is_https) {
            var tunnel_ctx = Store.TunnelContext{
                .proxy_host = p_host,
                .proxy_port = p_port,
                .target_host = if (Store.dns_resolve_len > 0) Store.dns_resolve_str[0..Store.dns_resolve_len] else identity,
                .target_port = port,
            };
            Store.tls_tunnel_ctx = &tunnel_ctx;
            defer Store.tls_tunnel_ctx = null;

            if (Store.debug_mode) {
                debug.print("\x1b[90m[DEBUG]\x1b[0m Connection pool lookup for HTTP Tunnel: {s}:{d}\n", .{ hostname.bytes, p_port });
            }

            return try client.connect(HostName{ .bytes = identity }, port, .tls);
        } else {
            var proxy_stack = Proxy{
                .protocol = if (Store.proxy_type == .https) .tls else .plain,
                .host = .{ .bytes = p_host },
                .port = p_port,
                .authorization = null,
                .supports_connect = true,
            };

            const saved_http = client.http_proxy;
            const saved_https = client.https_proxy;
            client.http_proxy = &proxy_stack;
            client.https_proxy = &proxy_stack;
            defer {
                client.http_proxy = saved_http;
                client.https_proxy = saved_https;
            }

            if (Store.debug_mode) {
                debug.print("\x1b[90m[DEBUG]\x1b[0m Connection pool lookup for standard proxy override: {s}:{d}\n", .{ hostname.bytes, p_port });
            }

            return try client.connect(HostName{ .bytes = identity }, port, protocol);
        }
    }

    const current_std_proxy = if (is_https) client.https_proxy else client.http_proxy;
    if (current_std_proxy != null) {
        if (Store.debug_mode) {
            debug.print("\x1b[90m[DEBUG]\x1b[0m Connection pool lookup via auto-detected proxy: {s}:{d}\n", .{ current_std_proxy.?.host.bytes, current_std_proxy.?.port });
        }

        return try client.connect(HostName{ .bytes = identity }, port, protocol);
    }

    const connect_host = if (Store.dns_resolve_len > 0) Store.dns_resolve_str[0..Store.dns_resolve_len] else hostname.bytes;

    if (Store.debug_mode) {
        debug.print("\x1b[90m[DEBUG]\x1b[0m Connection pool lookup for direct {s}:{d} (Identity: {s})\n", .{ connect_host, port, identity });
    }

    const conn = try client.connectTcpOptions(.{
        .host = .{ .bytes = connect_host },
        .port = port,
        .protocol = protocol,
        .proxied_host = HostName{ .bytes = identity },
    });
    conn.proxied = false;

    return conn;
}

pub fn fetchApiToBuffer(client: *Client, url_str: []const u8, auth: []const u8, buffer: []u8) ![]u8 {
    Store.net_req_fba.reset();
    const req_alloc = Store.net_req_fba.allocator();

    var uri = try Uri.parse(url_str);
    const conn = try getPinnedConnection(client, uri);

    const saved_http = client.http_proxy;
    const saved_https = client.https_proxy;
    if (mem.eql(u8, uri.scheme, "https")) {
        client.http_proxy = null;
        client.https_proxy = null;
    }
    defer {
        client.http_proxy = saved_http;
        client.https_proxy = saved_https;
    }

    if (Store.pinned_identity_len > 0) {
        if (uri.host) |*h| h.* = .{ .raw = Store.pinned_identity[0..Store.pinned_identity_len] };
    }

    var req = try client.request(.GET, uri, .{
        .connection = conn,
        .headers = .{
            .user_agent = .{ .override = Store.user_agent[0..Store.user_agent_len] },
            .accept_encoding = .{ .override = "gzip" },
        },
    });
    defer req.deinit();

    const extra_headers = try req_alloc.alloc(Header, 2);
    var extra_len: usize = 0;
    if (Store.session_cookie_len > 0) {
        extra_headers[extra_len] = .{ .name = "Cookie", .value = Store.session_cookie[0..Store.session_cookie_len] };
        extra_len += 1;
    } else if (auth.len > 0) {
        extra_headers[extra_len] = .{ .name = "Authorization", .value = auth };
        extra_len += 1;
    }
    req.extra_headers = extra_headers[0..extra_len];

    try req.sendBodiless();

    var redir_buffer: [4096]u8 = undefined;
    var response = try req.receiveHead(&redir_buffer);

    if (response.head.status == .unauthorized) return error.Unauthorized;
    if (response.head.status == .bad_gateway or response.head.status == .service_unavailable or response.head.status == .gateway_timeout) return error.ServiceUnavailable;
    if (response.head.status != .ok) {
        if (Store.debug_mode) {
            debug.print("\x1b[91m[DEBUG] API Rejected: {d}\x1b[0m\n", .{@intFromEnum(response.head.status)});
        }
        return error.ApiRequestRejected;
    }

    var is_gzip = false;
    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (ascii.eqlIgnoreCase(header.name, "Set-Cookie")) {
            if (mem.indexOf(u8, header.value, "agh_session=")) |_| {
                const val = header.value;
                const cookie_content = if (mem.indexOfScalar(u8, val, ';')) |idx| val[0..idx] else val;
                const safe_len = @min(cookie_content.len, Store.session_cookie.len);
                @memcpy(Store.session_cookie[0..safe_len], cookie_content[0..safe_len]);
                Store.session_cookie_len = safe_len;
                if (Store.debug_mode) debug.print("\x1b[90m[DEBUG]\x1b[0m Session Cookie Updated (API): {s}\n", .{Store.session_cookie[0..Store.session_cookie_len]});
            }
        } else if (ascii.eqlIgnoreCase(header.name, "Content-Encoding")) {
            if (mem.indexOf(u8, header.value, "gzip") != null) is_gzip = true;
        }
    }

    var transfer_buf: [4096]u8 = undefined;
    var body_len: usize = 0;
    var limit_state_buf: [1]u8 = undefined;

    if (is_gzip) {
        const raw_reader = response.reader(&transfer_buf);
        var decompressor = Decompress.init(raw_reader, .gzip, &gzip_window);
        var l_reader = decompressor.reader.limited(.limited(buffer.len), &limit_state_buf);
        body_len = try l_reader.interface.readSliceShort(buffer);
    } else {
        const raw_reader = response.reader(&transfer_buf);
        var l_reader = raw_reader.limited(.limited(buffer.len), &limit_state_buf);
        body_len = try l_reader.interface.readSliceShort(buffer);
    }

    Store.scratch_fba.end_index = body_len;

    if (Store.debug_mode) {
        var s_buf: [32]u8 = undefined;
        const size_str = Store.formatSize(&s_buf, body_len);
        debug.print("\x1b[90m[DEBUG]\x1b[0m API Request: {s} (Buffer: {s})\n", .{ url_str, size_str });
    }

    return buffer[0..body_len];
}

pub fn performLogin(client: *Client, url_str: []const u8, user: []const u8, pass: []const u8, _: Allocator) !void {
    Store.net_req_fba.reset();

    var uri = try Uri.parse(url_str);

    if (Store.debug_mode) {
        debug.print("\x1b[90m[DEBUG]\x1b[0m Attempting Login: {s}\n", .{url_str});
    }

    const conn = try getPinnedConnection(client, uri);

    const saved_http = client.http_proxy;
    const saved_https = client.https_proxy;
    if (mem.eql(u8, uri.scheme, "https")) {
        client.http_proxy = null;
        client.https_proxy = null;
    }
    defer {
        client.http_proxy = saved_http;
        client.https_proxy = saved_https;
    }

    if (Store.pinned_identity_len > 0) {
        if (uri.host) |*h| h.* = .{ .raw = Store.pinned_identity[0..Store.pinned_identity_len] };
    }

    var payload_buf: [512]u8 = undefined;
    const login_payload = try fmt.bufPrint(&payload_buf, "{{\"name\":\"{s}\",\"password\":\"{s}\"}}", .{ user, pass });
    defer crypto.secureZero(u8, &payload_buf);

    var req = try client.request(.POST, uri, .{
        .connection = conn,
        .headers = .{
            .user_agent = .{ .override = Store.user_agent[0..Store.user_agent_len] },
            .content_type = .{ .override = "application/json" },
        },
    });
    defer req.deinit();

    try req.sendBodyComplete(login_payload);

    var redir_buffer: [2048]u8 = undefined;
    var response = try req.receiveHead(&redir_buffer);

    if (response.head.status != .ok) {
        if (Store.debug_mode) {
            debug.print("\x1b[91m[DEBUG] Login Failed: {d}\x1b[0m\n", .{@intFromEnum(response.head.status)});
        }
        return switch (response.head.status) {
            .unauthorized => error.Unauthorized,
            .bad_gateway, .service_unavailable, .gateway_timeout => error.ServiceUnavailable,
            else => error.LoginFailed,
        };
    }

    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (ascii.eqlIgnoreCase(header.name, "Set-Cookie")) {
            if (mem.indexOf(u8, header.value, "agh_session=")) |start_idx| {
                const cookie_part = header.value[start_idx..];
                const end_rel = mem.indexOfScalar(u8, cookie_part, ';') orelse cookie_part.len;
                const final_cookie = cookie_part[0..end_rel];
                const safe_len = @min(final_cookie.len, Store.session_cookie.len);
                @memcpy(Store.session_cookie[0..safe_len], final_cookie[0..safe_len]);
                Store.session_cookie_len = safe_len;
                if (Store.debug_mode) {
                    debug.print("\x1b[90m[DEBUG]\x1b[0m Login Set-Cookie extracted: {s}\n", .{Store.session_cookie[0..Store.session_cookie_len]});
                }
            }
        }
    }
}

pub fn performLogout(client: *Client, base_url: []const u8, cookie: []const u8) !void {
    if (cookie.len == 0) return;

    if (Store.debug_mode) {
        debug.print("\x1b[90m[DEBUG]\x1b[0m Attempting Logout: {s}\n", .{cookie});
    }

    Store.net_req_fba.reset();
    const req_alloc = Store.net_req_fba.allocator();

    var url_buf: [512]u8 = undefined;
    const url_str = try fmt.bufPrint(&url_buf, "{s}/logout", .{base_url});
    var uri = try Uri.parse(url_str);

    const conn = try getPinnedConnection(client, uri);

    const saved_http = client.http_proxy;
    const saved_https = client.https_proxy;
    if (mem.eql(u8, uri.scheme, "https")) {
        client.http_proxy = null;
        client.https_proxy = null;
    }
    defer {
        client.http_proxy = saved_http;
        client.https_proxy = saved_https;
    }

    if (Store.pinned_identity_len > 0) {
        if (uri.host) |*h| h.* = .{ .raw = Store.pinned_identity[0..Store.pinned_identity_len] };
    }

    var req = try client.request(.GET, uri, .{
        .connection = conn,
        .headers = .{ .user_agent = .{ .override = Store.user_agent[0..Store.user_agent_len] } },
    });
    defer req.deinit();

    const extra_headers = try req_alloc.alloc(Header, 1);
    extra_headers[0] = .{ .name = "Cookie", .value = cookie };
    req.extra_headers = extra_headers;

    try req.sendBodiless();

    var redir_buffer: [1024]u8 = undefined;
    const response = try req.receiveHead(&redir_buffer);

    if (Store.debug_mode) {
        debug.print("\x1b[90m[DEBUG]\x1b[0m Logout Response: {d} {s}\n", .{ @intFromEnum(response.head.status), response.head.reason });
    }

    if (mem.eql(u8, cookie, Store.session_cookie[0..Store.session_cookie_len])) {
        crypto.secureZero(u8, &Store.session_cookie);
        Store.session_cookie_len = 0;
    }
}
