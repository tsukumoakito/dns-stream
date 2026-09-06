const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const debug = std.debug;
const net = Io.net;
const Clock = Io.Clock;
const VTable = Io.VTable;
const Writer = Io.Writer;
const Duration = Io.Duration;
const Queue = Io.Queue;
const Stream = Io.net.Stream;
const Socket = Io.net.Socket;
const HostName = Io.net.HostName;
const IpAddress = Io.net.IpAddress;
const Ip4Address = Io.net.Ip4Address;
const Ip6Address = Io.net.Ip6Address;
const ResolvConf = Io.net.HostName.ResolvConf;
const DnsResponse = Io.net.HostName.DnsResponse;
const LookupError = Io.net.HostName.LookupError;
const LookupResult = Io.net.HostName.LookupResult;
const LookupOptions = Io.net.HostName.LookupOptions;
const Allocator = mem.Allocator;

const Store = @import("../data/Store.zig");

const CLR_DBG = "\x1b[90m";
const CLR_SUC = "\x1b[32m";
const CLR_ERR = "\x1b[31m";
const CLR_RST = "\x1b[0m";

pub const SocksContext = struct {
    proxy_host: []const u8,
    proxy_port: u16,
    target_ip: []const u8,
    target_port: u16,
};

pub const TunnelContext = struct {
    proxy_host: []const u8,
    proxy_port: u16,
    target_host: []const u8,
    target_port: u16,
};

pub threadlocal var tls_socks_ctx: ?*SocksContext = null;
pub threadlocal var tls_tunnel_ctx: ?*TunnelContext = null;

var sniper_vtable: VTable = undefined;
var original_vtable: VTable = undefined;
var sniper_vtable_initialized: bool = false;

pub fn createSniperIo(base_io: Io) Io {
    if (!sniper_vtable_initialized) {
        original_vtable = base_io.vtable.*;
        sniper_vtable = base_io.vtable.*;
        sniper_vtable.netConnectIp = sniperConnectIpHook;
        sniper_vtable.netRead = sniperReadHook;
        sniper_vtable.netWrite = sniperWriteHook;
        sniper_vtable.netLookup = sniperLookupHook;
        sniper_vtable_initialized = true;
    }
    return .{ .vtable = &sniper_vtable, .userdata = base_io.userdata };
}

fn sniperLookupHook(userdata: ?*anyopaque, host_name: HostName, resolved: *Queue(LookupResult), options: LookupOptions) LookupError!void {
    const clean_io = Io{ .vtable = &original_vtable, .userdata = userdata };

    if (IpAddress.parse(host_name.bytes, options.port)) |addr| {
        resolved.putOneUncancelable(clean_io, .{ .address = addr }) catch |err| switch (err) {
            error.Closed => {},
        };
        resolved.close(clean_io);
        return;
    } else |_| {}

    if (Store.dns_resolve_len > 0 and Store.dns_resolve_host_len > 0) {
        const cached_host = Store.dns_resolve_host[0..Store.dns_resolve_host_len];
        if (mem.eql(u8, host_name.bytes, cached_host)) {
            const cached_ip = Store.dns_resolve_str[0..Store.dns_resolve_len];
            if (IpAddress.parse(cached_ip, options.port)) |addr| {
                resolved.putOneUncancelable(clean_io, .{ .address = addr }) catch |err| switch (err) {
                    error.Closed => {},
                };
                resolved.close(clean_io);
                return;
            } else |_| {}
        }
    }

    return original_vtable.netLookup(userdata, host_name, resolved, options);
}

fn sniperReadHook(userdata: ?*anyopaque, handle: Socket.Handle, data: [][]u8) Stream.Reader.Error!usize {
    return original_vtable.netRead(userdata, handle, data);
}

fn sniperWriteHook(userdata: ?*anyopaque, handle: Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) Stream.Writer.Error!usize {
    return original_vtable.netWrite(userdata, handle, header, data, splat);
}

fn sniperConnectIpHook(userdata: ?*anyopaque, addr: *const IpAddress, options: IpAddress.ConnectOptions) IpAddress.ConnectError!Socket {
    const clean_io = Io{ .vtable = &original_vtable, .userdata = userdata };

    if (tls_socks_ctx) |ctx| {
        const handle = socks5ConnectRaw(clean_io, ctx.proxy_host, ctx.proxy_port, ctx.target_ip, ctx.target_port) catch |err| {
            if (Store.debug_mode) debug.print("{s}[DEBUG] SOCKS5 connection failed: {any}{s}\n", .{ CLR_DBG, err, CLR_RST });
            return error.ConnectionRefused;
        };
        return Socket{ .handle = handle, .address = addr.* };
    }

    if (tls_tunnel_ctx) |ctx| {
        const handle = httpConnectTunnelRaw(clean_io, ctx.proxy_host, ctx.proxy_port, ctx.target_host, ctx.target_port) catch |err| {
            if (Store.debug_mode) debug.print("{s}[DEBUG] HTTP Tunnel failed: {any}{s}\n", .{ CLR_DBG, err, CLR_RST });
            return error.ConnectionRefused;
        };
        return Socket{ .handle = handle, .address = addr.* };
    }

    return original_vtable.netConnectIp(userdata, addr, options);
}

pub fn probeTlsIdentity(io: Io, allocator: Allocator, ip: []const u8, port: u16) !?[]const u8 {
    if (try probeTlsIdentityInternal(io, allocator, ip, port, null)) |identity| {
        return identity;
    }

    if (Store.debug_mode) debug.print("{s}[DEBUG] SNIPE: Blind snipe failed. Attempting PTR fallback for {s}...{s}\n", .{ CLR_DBG, ip, CLR_RST });

    if (try reverseDnsLookup(io, allocator, ip)) |ptr_name| {
        defer allocator.free(ptr_name);
        if (Store.debug_mode) debug.print("{s}[DEBUG] SNIPE: PTR found: {s}. Retrying with SNI...{s}\n", .{ CLR_DBG, ptr_name, CLR_RST });
        return try probeTlsIdentityInternal(io, allocator, ip, port, ptr_name);
    }

    if (Store.debug_mode) debug.print("{s}[DEBUG] SNIPE: PTR fallback failed or no record found.{s}\n", .{ CLR_ERR, CLR_RST });
    return null;
}

fn probeTlsIdentityInternal(io: Io, allocator: Allocator, ip: []const u8, port: u16, sni_name: ?[]const u8) !?[]const u8 {
    if (Store.debug_mode) debug.print("{s}[DEBUG] Probing TLS Identity via Binary Snipe (SNI: {s})...{s}\n", .{ CLR_DBG, sni_name orelse "none", CLR_RST });

    const ip_addr = try IpAddress.parse(ip, port);
    const stream = try ip_addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var packet_buf: [1024]u8 = undefined;
    var f_writer = Writer.fixed(&packet_buf);
    var w = &f_writer;

    try w.writeAll(&.{ 0x16, 0x03, 0x01, 0x00, 0x00 });
    const hs_start = w.buffered().len;

    try w.writeAll(&.{ 0x01, 0x00, 0x00, 0x00 });
    const ch_start = w.buffered().len;

    try w.writeAll(&.{ 0x03, 0x03 });
    try w.splatByteAll(0x55, 32);
    try w.writeByte(0x00);
    try w.writeAll(&.{ 0x00, 0x04, 0xc0, 0x2f, 0x00, 0x9c });
    try w.writeAll(&.{ 0x01, 0x00 });

    const ext_len_pos = w.buffered().len;
    try w.writeAll(&.{ 0x00, 0x00 });

    if (sni_name) |name| {
        try w.writeAll(&.{ 0x00, 0x00 });
        const sni_ext_total_pos = w.buffered().len;
        try w.writeAll(&.{ 0x00, 0x00 });
        const sni_list_pos = w.buffered().len;
        try w.writeAll(&.{ 0x00, 0x00 });
        try w.writeByte(0x00);
        const name_len_pos = w.buffered().len;
        try w.writeAll(&.{ 0x00, 0x00 });
        try w.writeAll(name);

        const name_len = @as(u16, @intCast(name.len));
        mem.writeInt(u16, packet_buf[name_len_pos .. name_len_pos + 2][0..2], name_len, .big);
        mem.writeInt(u16, packet_buf[sni_list_pos .. sni_list_pos + 2][0..2], name_len + 3, .big);
        mem.writeInt(u16, packet_buf[sni_ext_total_pos .. sni_ext_total_pos + 2][0..2], name_len + 5, .big);
    }

    try w.writeAll(&.{ 0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x04, 0x01 });
    try w.writeAll(&.{ 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17 });

    const end_pos = w.buffered().len;

    mem.writeInt(u16, packet_buf[3..5][0..2], @intCast(end_pos - hs_start), .big);
    mem.writeInt(u24, packet_buf[hs_start + 1 .. hs_start + 4][0..3], @intCast(end_pos - ch_start), .big);
    mem.writeInt(u16, packet_buf[ext_len_pos .. ext_len_pos + 2][0..2], @intCast(end_pos - ext_len_pos - 2), .big);

    _ = try io.vtable.netWrite(io.userdata, stream.socket.handle, "", &.{packet_buf[0..end_pos]}, 1);

    var resp_buf = try allocator.alloc(u8, 16384);
    defer allocator.free(resp_buf);

    var total: usize = 0;
    const cn_oid = &[_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 };

    while (total < resp_buf.len) {
        var iov = [_][]u8{resp_buf[total..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &iov);
        if (n == 0) break;
        total += n;
        if (mem.indexOf(u8, resp_buf[0..total], cn_oid)) |_| break;
    }

    const raw = resp_buf[0..total];
    var s_idx: usize = 0;
    while (mem.indexOfPos(u8, raw, s_idx, cn_oid)) |idx| {
        s_idx = idx + cn_oid.len;
        if (raw.len > s_idx + 2) {
            const l = raw[s_idx + 1];
            const s = s_idx + 2;
            if (raw.len >= s + l) {
                const id = raw[s .. s + l];
                if (mem.indexOfScalar(u8, id, '.') != null and !isIpAddress(id)) {
                    const discovered = try allocator.dupe(u8, id);
                    if (Store.debug_mode) debug.print("{s}[DEBUG] Found TLS Identity: {s}{s}\n", .{ CLR_SUC, discovered, CLR_RST });
                    return discovered;
                }
            }
        }
    }
    return null;
}

pub fn reverseDnsLookup(io: Io, allocator: Allocator, ip: []const u8) !?[]const u8 {
    const addr = try IpAddress.parse(ip, 0);

    if (Store.debug_mode) debug.print("{s}[DEBUG] PTR: Initiating reverse lookup for {s}...{s}\n", .{ CLR_DBG, ip, CLR_RST });

    var arpa_buf: [128]u8 = undefined;
    const arpa_name = switch (addr) {
        .ip4 => |ip4| try fmt.bufPrint(&arpa_buf, "{d}.{d}.{d}.{d}.in-addr.arpa", .{
            ip4.bytes[3],
            ip4.bytes[2],
            ip4.bytes[1],
            ip4.bytes[0],
        }),
        .ip6 => |ip6| b: {
            var p: usize = 0;
            var j: i16 = 15;
            while (j >= 0) : (j -= 1) {
                const byte = ip6.bytes[@intCast(j)];
                p += (try fmt.bufPrint(arpa_buf[p..], "{x}.{x}.", .{ byte & 0x0F, (byte >> 4) & 0x0F })).len;
            }
            const suffix = "ip6.arpa";
            @memcpy(arpa_buf[p .. p + suffix.len], suffix);
            break :b arpa_buf[0 .. p + suffix.len];
        },
    };

    const rc = try ResolvConf.init(io);
    const dns_servers = rc.nameservers();
    if (dns_servers.len == 0) return error.NoNameServers;
    const dns_target = dns_servers[0];

    var packet_buf: [512]u8 = undefined;
    var f_writer = Writer.fixed(&packet_buf);
    var w = &f_writer;

    try w.writeAll(&.{ 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
    var it = mem.splitScalar(u8, arpa_name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        try w.writeByte(@intCast(label.len));
        try w.writeAll(label);
    }
    try w.writeByte(0);
    try w.writeAll(&.{ 0x00, 0x0c, 0x00, 0x01 });

    const sock = try IpAddress.bind(&IpAddress{ .ip4 = Ip4Address.unspecified(0) }, io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer sock.close(io);

    try sock.send(io, &dns_target, packet_buf[0..w.buffered().len]);

    var recv_buf: [1024]u8 = undefined;
    const deadline = Clock.Timestamp.now(io, .real).addDuration(.{
        .raw = Duration.fromMilliseconds(2000),
        .clock = .real,
    });

    const incoming = try sock.receiveTimeout(io, &recv_buf, .{ .deadline = deadline });
    const packet = incoming.data;
    if (packet.len < 12) return null;
    const q_count = mem.readInt(u16, packet[4..6][0..2], .big);
    const ans_count = mem.readInt(u16, packet[6..8][0..2], .big);
    var pos: usize = 12;
    var i: usize = 0;
    while (i < q_count) : (i += 1) {
        while (pos < packet.len) {
            const b = packet[pos];
            if (b == 0) {
                pos += 1;
                break;
            }
            if (b >= 192) {
                pos += 2;
                break;
            }
            pos += @as(usize, b) + 1;
        }
        pos += 4;
    }
    var a: usize = 0;
    while (a < ans_count and pos + 10 <= packet.len) : (a += 1) {
        while (pos < packet.len) {
            const b = packet[pos];
            if (b == 0) {
                pos += 1;
                break;
            }
            if (b >= 192) {
                pos += 2;
                break;
            }
            pos += @as(usize, b) + 1;
        }
        if (pos + 10 > packet.len) break;
        const rr_type = mem.readInt(u16, packet[pos .. pos + 2][0..2], .big);
        const data_len = mem.readInt(u16, packet[pos + 8 .. pos + 10][0..2], .big);
        const data_off = pos + 10;
        if (rr_type == 12) {
            var name_out_buf: [HostName.max_len]u8 = undefined;
            const expanded = try HostName.expand(packet, data_off, &name_out_buf);
            var result_name = expanded[1].bytes;
            if (mem.endsWith(u8, result_name, ".")) result_name = result_name[0 .. result_name.len - 1];

            if (Store.debug_mode) debug.print("{s}[DEBUG] PTR: Found name: \"{s}\"{s}\n", .{ CLR_SUC, result_name, CLR_RST });
            return try allocator.dupe(u8, result_name);
        }
        pos = data_off + data_len;
    }

    return null;
}

fn httpConnectTunnelRaw(clean_io: Io, ph: []const u8, pp: u16, th: []const u8, tp: u16) !Socket.Handle {
    const p_ip = try resolveHostToIp(clean_io, ph, pp);
    const stream = try p_ip.connect(clean_io, .{ .mode = .stream });
    errdefer stream.close(clean_io);

    var req_buf: [256]u8 = undefined;
    const req = try fmt.bufPrint(&req_buf, "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n\r\n", .{ th, tp, th, tp });
    _ = try clean_io.vtable.netWrite(clean_io.userdata, stream.socket.handle, "", &.{req}, 1);

    var resp_buf: [1024]u8 = undefined;
    var iov = [_][]u8{&resp_buf};
    const n = try clean_io.vtable.netRead(clean_io.userdata, stream.socket.handle, &iov);
    if (n == 0 or !mem.containsAtLeast(u8, resp_buf[0..n], 1, "200")) return error.TunnelFailed;

    return stream.socket.handle;
}

fn socks5ConnectRaw(clean_io: Io, ph: []const u8, pp: u16, ti: []const u8, tp: u16) !Socket.Handle {
    const p_ip = try resolveHostToIp(clean_io, ph, pp);
    const stream = try p_ip.connect(clean_io, .{ .mode = .stream });
    errdefer stream.close(clean_io);

    _ = try clean_io.vtable.netWrite(clean_io.userdata, stream.socket.handle, "", &.{&.{ 0x05, 0x01, 0x00 }}, 1);

    var buf: [10]u8 = undefined;
    var iov = [_][]u8{buf[0..2]};
    _ = try clean_io.vtable.netRead(clean_io.userdata, stream.socket.handle, &iov);
    if (buf[0] != 0x05 or buf[1] != 0x00) return error.Socks5AuthFailed;

    const t_addr = try IpAddress.parse(ti, tp);
    var req: [22]u8 = undefined;
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    var req_len: usize = 0;
    switch (t_addr) {
        .ip4 => |ip4| {
            req[3] = 0x01;
            @memcpy(req[4..8], &ip4.bytes);
            mem.writeInt(u16, req[8..10][0..2], tp, .big);
            req_len = 10;
        },
        .ip6 => |ip6| {
            req[3] = 0x04;
            @memcpy(req[4..20], &ip6.bytes);
            mem.writeInt(u16, req[20..22][0..2], tp, .big);
            req_len = 22;
        },
    }

    _ = try clean_io.vtable.netWrite(clean_io.userdata, stream.socket.handle, "", &.{req[0..req_len]}, 1);

    iov[0] = buf[0..4];
    _ = try clean_io.vtable.netRead(clean_io.userdata, stream.socket.handle, &iov);
    if (buf[1] != 0x00) return error.Socks5ConnectFailed;
    if (buf[3] == 0x01) {
        iov[0] = buf[0..6];
        _ = try clean_io.vtable.netRead(clean_io.userdata, stream.socket.handle, &iov);
    }

    return stream.socket.handle;
}

pub fn resolveHostToIp(io: Io, host: []const u8, port: u16) !IpAddress {
    if (IpAddress.parse(host, port)) |ip| return ip else |_| {}

    const host_name = try HostName.init(host);
    var queue_buf: [16]LookupResult = undefined;
    var queue = Queue(LookupResult).init(&queue_buf);

    try host_name.lookup(io, &queue, .{ .port = port });

    while (true) {
        const result = try queue.getOneUncancelable(io);
        switch (result) {
            .address => |addr| return addr,
            .canonical_name => continue,
        }
    }
}

pub fn isIpAddress(text: []const u8) bool {
    _ = IpAddress.parse(text, 0) catch return false;
    return true;
}
