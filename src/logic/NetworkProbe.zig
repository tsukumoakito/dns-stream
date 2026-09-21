const std = @import("std");
const Io = std.Io;
const net = Io.net;
const Uri = std.Uri;
const mem = std.mem;
const fmt = std.fmt;
const heap = std.heap;
const http = std.http;
const debug = std.debug;
const Clock = Io.Clock;
const Duration = Io.Duration;
const Queue = Io.Queue;
const Stream = Io.net.Stream;
const Socket = Io.net.Socket;
const HostName = Io.net.HostName;
const IpAddress = Io.net.IpAddress;
const Ip4Address = Io.net.Ip4Address;
const Ip6Address = Io.net.Ip6Address;
const LookupResult = Io.net.HostName.LookupResult;
const Select = Io.Select;
const Status = http.Status;
const Client = http.Client;
const Allocator = mem.Allocator;
const FixedBufferAllocator = heap.FixedBufferAllocator;

const Store = @import("../data/Store.zig");
const Network = @import("Network.zig");

pub const DNSStrategy = enum { local, remote };
pub const SnipeRole = enum { discovery, verification, none };

pub const Resolution = struct {
    address: IpAddress,
    canonical_name: ?[]const u8 = null,
};

pub const ProbeError = error{
    ProxyConnectionFailed,
    ProxyProtocolMismatch,
    ProxyAuthenticationRequired,
    TunnelEstablishmentFailed,
    IdentityVerificationFailed,
    IdentityDiscoveryFailed,
    TargetUnreachable,
    TargetRejected,
    DnsResolutionFailed,
    TlsHandshakeFailed,
    InvalidUrl,
    Timeout,
};

pub const ProbeResult = struct {
    status: Status,
    target_url: []const u8,
    resolved_ip: ?[]const u8,
    pinned_identity: ?[]const u8,
};

const InternalReadResult = union(enum) {
    n: anyerror!usize,
    timeout: void,
};

const InternalConnectResult = union(enum) {
    stream: anyerror!Stream,
    timeout: void,
};

pub const ProbeTask = struct {
    allocator: Allocator,
    io: Io,
    target_url: []const u8,
    proxy_url: ?[]const u8 = null,
    dns_strategy: DNSStrategy = .remote,
    forced_ip: ?[]const u8 = null,
    forced_identity: ?[]const u8 = null,
    debug: bool = false,

    pub fn execute(self: *ProbeTask) !ProbeResult {
        const uri = Uri.parse(self.target_url) catch |err| {
            if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] Uri.parse failed: {any}\x1b[0m\n", .{err});
            return err;
        };
        const is_https = mem.eql(u8, uri.scheme, "https");
        const port = uri.port orelse (if (is_https) @as(u16, 443) else @as(u16, 80));

        var h_buf: [HostName.max_len]u8 = undefined;
        const hostname = uri.getHost(&h_buf) catch |err| {
            if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] uri.getHost failed: {any}\x1b[0m\n", .{err});
            return err;
        };

        var target_addr: ?IpAddress = null;
        var dns_identity: ?[]const u8 = null;
        errdefer if (dns_identity) |id| self.allocator.free(id);
        const is_ip_target = Network.isIpAddress(hostname.bytes);
        if (self.forced_ip) |f_ip| {
            target_addr = IpAddress.parse(f_ip, port) catch |err| {
                if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] IpAddress.parse failed: {any}\x1b[0m\n", .{err});
                return err;
            };
        } else if (self.dns_strategy == .local or is_ip_target) {
            const res = resolveHostToIp(self.io, self.allocator, hostname.bytes, port) catch |err| {
                if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] resolveHostToIp failed: {any}\x1b[0m\n", .{err});
                return error.DnsResolutionFailed;
            };
            target_addr = res.address;
            dns_identity = res.canonical_name;
        }

        var stream: Stream = undefined;
        if (self.proxy_url) |p_url| {
            const connect_host = if (target_addr) |addr| blk: {
                var ip_buf: [64]u8 = undefined;
                break :blk self.allocator.dupe(u8, formatIp(&ip_buf, addr) catch "") catch return error.OutofMemory;
            } else self.allocator.dupe(u8, hostname.bytes) catch return error.OutofMemory;
            defer self.allocator.free(connect_host);

            stream = self.connectViaProxy(p_url, connect_host, port, is_https) catch |err| {
                if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] connectViaProxy failed: {any}\x1b[0m\n", .{err});
                return err;
            };
        } else {
            const final_addr = if (target_addr) |addr| addr else blk: {
                const res = resolveHostToIp(self.io, self.allocator, hostname.bytes, port) catch |err| {
                    if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] fallback resolveHostToIp failed: {any}\x1b[0m\n", .{err});
                    return error.DnsResolutionFailed;
                };
                if (dns_identity == null) dns_identity = res.canonical_name;
                break :blk res.address;
            };
            target_addr = final_addr;
            stream = self.connectWithTimeout(final_addr) catch |err| {
                if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] connectWithTimeout failed: {any}\x1b[0m\n", .{err});
                return err;
            };
        }
        defer stream.close(self.io);

        var final_identity: ?[]const u8 = null;
        errdefer if (final_identity) |id| self.allocator.free(id);

        if (self.forced_identity) |f_id| {
            final_identity = self.allocator.dupe(u8, f_id) catch return error.OutofMemory;
        } else if (dns_identity) |cn| {
            final_identity = self.allocator.dupe(u8, cn) catch return error.OutofMemory;
        } else if (!is_ip_target) {
            final_identity = self.allocator.dupe(u8, hostname.bytes) catch return error.OutofMemory;
        }

        const snipe_role = self.determineSnipeRole(is_https, is_ip_target);

        if (snipe_role != .none and target_addr != null) {
            var ip_buf: [64]u8 = undefined;
            const ip_str = formatIp(&ip_buf, target_addr.?) catch "";

            var snipe_scratch: [32768]u8 align(16) = undefined;
            var snipe_fba = FixedBufferAllocator.init(&snipe_scratch);
            const disc_res = Network.probeTlsIdentity(self.io, snipe_fba.allocator(), ip_str, port) catch |err| {
                if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] probeTlsIdentity threw error: {any}\x1b[0m\n", .{err});
                return err;
            };

            if (disc_res) |disc| {
                if (snipe_role == .verification and self.forced_identity == null) {
                    const check_name = dns_identity orelse hostname.bytes;
                    if (!mem.eql(u8, disc, check_name)) return error.IdentityVerificationFailed;
                } else if (snipe_role == .discovery and self.forced_identity == null) {
                    if (final_identity) |old| self.allocator.free(old);
                    final_identity = self.allocator.dupe(u8, disc) catch return error.OutofMemory;
                }
            } else if (snipe_role == .discovery and self.forced_identity == null) {
                return error.IdentityDiscoveryFailed;
            }
        }

        var client_buf: [131072]u8 align(16) = undefined;
        var client_fba = FixedBufferAllocator.init(&client_buf);
        var client = Client{
            .allocator = client_fba.allocator(),
            .io = self.io,
            .ca_bundle = if (Store.shared_ca_bundle) |b| b.* else .empty,
            .now = Clock.real.now(self.io),
        };

        if (self.debug) {
            debug.print("\x1b[92m[PROBE-DEBUG] CA bundle rescan completed (Memory used: {d} bytes).\x1b[0m\n", .{client_fba.end_index});
        }

        if (self.proxy_url) |p_url| {
            const p_uri = Uri.parse(p_url) catch return error.InvalidUrl;
            var p_host_buf: [HostName.max_len]u8 = undefined;
            const p_host = p_uri.getHost(&p_host_buf) catch return error.InvalidUrl;
            var proxy_stack = Client.Proxy{
                .protocol = if (mem.eql(u8, p_uri.scheme, "https")) .tls else .plain,
                .host = p_host,
                .port = p_uri.port orelse 8080,
                .authorization = null,
                .supports_connect = true,
            };
            client.http_proxy = &proxy_stack;
            client.https_proxy = &proxy_stack;
        }

        const identity_to_use = final_identity orelse hostname.bytes;
        const current_target_str = if (target_addr) |addr| blk: {
            var buf: [64]u8 = undefined;
            break :blk self.allocator.dupe(u8, formatIp(&buf, addr) catch "") catch return error.OutofMemory;
        } else self.allocator.dupe(u8, hostname.bytes) catch return error.OutofMemory;
        defer self.allocator.free(current_target_str);

        if (self.debug) {
            debug.print("\x1b[96m[PROBE-DEEP-DEBUG] Attempting connectTcpOptions for host: {s}, proxied_host: {s}, port: {d}, protocol: {s}\x1b[0m\n", .{
                current_target_str,
                identity_to_use,
                port,
                if (is_https) "tls" else "plain",
            });
        }

        const conn = client.connectTcpOptions(.{
            .host = .{ .bytes = current_target_str },
            .port = port,
            .protocol = if (is_https) .tls else .plain,
            .proxied_host = HostName{ .bytes = identity_to_use },
        }) catch |err| {
            if (self.debug) {
                debug.print("\x1b[91m[PROBE-DEEP-DEBUG] ❌ connectTcpOptions FAILED!\x1b[0m\n", .{});
                debug.print("\x1b[91m[PROBE-DEEP-DEBUG] Returned Error: {any} (Name: {s})\x1b[0m\n", .{ err, @errorName(err) });
            }
            return err;
        };

        if (self.debug) {
            debug.print("\x1b[92m[PROBE-DEEP-DEBUG] ✅ connectTcpOptions SUCCEEDED!\x1b[0m\n", .{});
        }

        var req = client.request(.GET, uri, .{
            .connection = conn,
            .redirect_behavior = .unhandled,
        }) catch |err| {
            if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] client.request failed: {any}\x1b[0m\n", .{err});
            return err;
        };
        defer req.deinit();

        req.sendBodiless() catch |err| {
            if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] req.sendBodiless failed: {any}\x1b[0m\n", .{err});
            return err;
        };

        var head_buf: [1024]u8 = undefined;
        const response = req.receiveHead(&head_buf) catch |err| {
            if (self.debug) debug.print("\x1b[91m[PROBE-DEBUG] req.receiveHead failed: {any}\x1b[0m\n", .{err});
            return err;
        };

        const class = response.head.status.class();
        if (class != .success and class != .redirect) {
            if (self.debug) debug.print("\x1b[31m[PROBE-DEBUG] Probe Rejected: Status {d} {s}\n", .{ @intFromEnum(response.head.status), response.head.reason });
            return error.TargetRejected;
        }

        const final_ip_str = if (target_addr) |addr| blk: {
            var buf: [64]u8 = undefined;
            break :blk self.allocator.dupe(u8, formatIp(&buf, addr) catch "") catch return error.OutofMemory;
        } else null;

        return .{
            .status = response.head.status,
            .target_url = self.target_url,
            .resolved_ip = final_ip_str,
            .pinned_identity = final_identity,
        };
    }

    fn connectWithTimeout(self: *ProbeTask, addr: IpAddress) !Stream {
        var sel_buf: [2]InternalConnectResult = undefined;
        var sel = Select(InternalConnectResult).init(self.io, &sel_buf);

        sel.async(.stream, struct {
            fn task(io_p: Io, a: IpAddress) anyerror!Stream {
                return a.connect(io_p, .{ .mode = .stream });
            }
        }.task, .{ self.io, addr });

        sel.async(.timeout, struct {
            fn task(io_p: Io) void {
                io_p.sleep(Duration.fromMilliseconds(5000), .awake) catch {};
            }
        }.task, .{self.io});

        const res = try sel.await();
        sel.cancelDiscard();

        return switch (res) {
            .stream => |s_res| s_res catch return error.TargetUnreachable,
            .timeout => return error.Timeout,
        };
    }

    fn connectViaProxy(self: *ProbeTask, p_url: []const u8, target: []const u8, port: u16, is_https: bool) !Stream {
        const p_uri = try Uri.parse(p_url);
        const p_is_https = mem.eql(u8, p_uri.scheme, "https");
        const p_is_socks = mem.startsWith(u8, p_uri.scheme, "socks5");

        var ph_buf: [HostName.max_len]u8 = undefined;
        const p_host = (try p_uri.getHost(&ph_buf)).bytes;
        const p_port = p_uri.port orelse 8080;

        const res = try resolveHostToIp(self.io, self.allocator, p_host, p_port);
        if (res.canonical_name) |cn| self.allocator.free(cn);

        var stream = try self.connectWithTimeout(res.address);
        errdefer stream.close(self.io);

        if (p_is_https) {
            var client_buf: [32768]u8 align(16) = undefined;
            var client_fba = FixedBufferAllocator.init(&client_buf);
            var client = Client{
                .allocator = client_fba.allocator(),
                .io = self.io,
                .ca_bundle = if (Store.shared_ca_bundle) |b| b.* else .empty,
                .now = Clock.real.now(self.io),
            };

            if (self.debug) {
                debug.print("\x1b[92m[PROBE-DEBUG] CA bundle rescan completed (Memory used: {d} bytes).\x1b[0m\n", .{client_fba.end_index});
            }
            _ = client.connect(HostName{ .bytes = p_host }, p_port, .tls) catch return error.ProxyProtocolMismatch;
        }

        if (p_is_socks) {
            try self.handshakeSocks5(stream, target, port);
        } else {
            try self.handshakeHttpConnect(stream, target, port, is_https);
        }

        return stream;
    }

    fn handshakeSocks5(self: *ProbeTask, stream: Stream, target: []const u8, port: u16) !void {
        try self.writeFull(stream, &.{ 0x05, 0x01, 0x00 });
        var buf: [256]u8 = undefined;

        const first_byte = try self.readByteWithTimeout(stream, 5000);
        if (first_byte == 0x48) return error.ProxyProtocolMismatch;
        if (first_byte != 0x05) return error.ProxyProtocolMismatch;

        try self.readFull(stream, buf[1..2]);
        if (buf[1] != 0x00) return error.ProxyAuthenticationRequired;

        var req: [262]u8 = undefined;
        req[0] = 0x05;
        req[1] = 0x01;
        req[2] = 0x00;

        var req_len: usize = 0;
        if (IpAddress.parse(target, port)) |addr| {
            switch (addr) {
                .ip4 => |ip4| {
                    req[3] = 0x01;
                    @memcpy(req[4..8], &ip4.bytes);
                    mem.writeInt(u16, req[8..10][0..2], port, .big);
                    req_len = 10;
                },
                .ip6 => |ip6| {
                    req[3] = 0x04;
                    @memcpy(req[4..20], &ip6.bytes);
                    mem.writeInt(u16, req[20..22][0..2], port, .big);
                    req_len = 22;
                },
            }
        } else |_| {
            req[3] = 0x03;
            req[4] = @intCast(target.len);
            @memcpy(req[5 .. 5 + target.len], target);
            mem.writeInt(u16, req[5 + target.len .. 7 + target.len][0..2], port, .big);
            req_len = 7 + target.len;
        }

        try self.writeFull(stream, req[0..req_len]);

        const resp_ver = try self.readByteWithTimeout(stream, 5000);
        if (resp_ver != 0x05) return error.ProxyProtocolMismatch;

        try self.readFull(stream, buf[1..4]);
        if (buf[1] != 0x00) return error.TunnelEstablishmentFailed;

        const atyp = buf[3];
        if (atyp == 0x01) {
            try self.readFull(stream, buf[0..6]);
        } else if (atyp == 0x03) {
            try self.readFull(stream, buf[0..1]);
            const d_len = buf[0];
            var d_buf: [258]u8 = undefined;
            try self.readFull(stream, d_buf[0 .. d_len + 2]);
        } else if (atyp == 0x04) {
            try self.readFull(stream, buf[0..18]);
        }
    }

    fn handshakeHttpConnect(self: *ProbeTask, stream: Stream, target: []const u8, port: u16, is_https: bool) !void {
        if (!is_https) return;
        var req_buf: [256]u8 = undefined;
        const req = try fmt.bufPrint(&req_buf, "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n\r\n", .{ target, port, target, port });
        try self.writeFull(stream, req);

        var resp_buf: [1024]u8 = undefined;
        const first_byte = try self.readByteWithTimeout(stream, 5000);
        resp_buf[0] = first_byte;

        var iov = [_][]u8{resp_buf[1..]};
        const n = try self.io.vtable.netRead(self.io.userdata, stream.socket.handle, &iov);
        const total = n + 1;

        if (!mem.startsWith(u8, resp_buf[0..total], "HTTP/")) return error.ProxyProtocolMismatch;
        if (!mem.containsAtLeast(u8, resp_buf[0..total], 1, "200")) return error.TunnelEstablishmentFailed;
    }

    fn readByteWithTimeout(self: *ProbeTask, stream: Stream, ms: u64) !u8 {
        var out_byte: u8 = undefined;
        var sel_buf: [2]InternalReadResult = undefined;
        var sel = Select(InternalReadResult).init(self.io, &sel_buf);

        sel.async(.n, struct {
            fn task(io_p: Io, handle: Socket.Handle, ptr: *u8) anyerror!usize {
                var b: [1]u8 = undefined;
                var iov = [_][]u8{&b};
                const n = try io_p.vtable.netRead(io_p.userdata, handle, &iov);
                if (n > 0) ptr.* = b[0];
                return n;
            }
        }.task, .{ self.io, stream.socket.handle, &out_byte });

        sel.async(.timeout, struct {
            fn task(io_p: Io, d: u64) void {
                io_p.sleep(Duration.fromMilliseconds(@intCast(d)), .awake) catch {};
            }
        }.task, .{ self.io, ms });

        const res = try sel.await();
        sel.cancelDiscard();

        switch (res) {
            .n => |n_res| {
                const n = try n_res;
                if (n == 0) return error.TargetUnreachable;
                return out_byte;
            },
            .timeout => return error.Timeout,
        }
    }

    fn writeFull(self: *ProbeTask, stream: Stream, data: []const u8) !void {
        var sent: usize = 0;
        while (sent < data.len) {
            const n = try self.io.vtable.netWrite(self.io.userdata, stream.socket.handle, "", &.{data[sent..]}, 1);
            if (n == 0) return error.TargetUnreachable;
            sent += n;
        }
    }

    fn readFull(self: *ProbeTask, stream: Stream, buffer: []u8) !void {
        var received: usize = 0;
        while (received < buffer.len) {
            var iov = [_][]u8{buffer[received..]};
            const n = try self.io.vtable.netRead(self.io.userdata, stream.socket.handle, &iov);
            if (n == 0) return error.TargetUnreachable;
            received += n;
        }
    }

    fn determineSnipeRole(self: *ProbeTask, is_https: bool, is_ip_target: bool) SnipeRole {
        if (!is_https) return .none;
        if (self.forced_identity != null) return .none;
        if (is_ip_target) return .discovery;
        return .none;
    }
};

pub fn resolveHostToIp(io: Io, allocator: Allocator, host: []const u8, port: u16) !Resolution {
    const parsed = IpAddress.parse(host, port) catch null;
    if (parsed) |ip| {
        var result = ip;
        if (result.getPort() == 0) result.setPort(port);
        return .{ .address = result, .canonical_name = null };
    }

    const host_name = try HostName.init(host);
    var queue_buf: [16]LookupResult = undefined;
    var queue = Queue(LookupResult).init(&queue_buf);
    try host_name.lookup(io, &queue, .{ .port = port });

    var canonical_name: ?[]const u8 = null;
    while (true) {
        const result = try queue.getOneUncancelable(io);
        switch (result) {
            .address => |addr| {
                var final_addr = addr;
                if (final_addr.getPort() == 0) final_addr.setPort(port);
                return .{ .address = final_addr, .canonical_name = canonical_name };
            },
            .canonical_name => |name| {
                if (canonical_name) |old| allocator.free(old);
                canonical_name = try allocator.dupe(u8, name.bytes);
            },
        }
    }
}

pub fn formatIp(buf: []u8, addr: IpAddress) ![]const u8 {
    var w = Io.Writer.fixed(buf);
    switch (addr) {
        .ip4 => |a| try w.print("{d}.{d}.{d}.{d}", .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3] }),
        .ip6 => |a| {
            const unresolved = net.Ip6Address.Unresolved{ .bytes = a.bytes, .interface_name = null };
            try unresolved.format(&w);
        },
    }
    return w.buffered();
}
