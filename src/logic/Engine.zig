const std = @import("std");
const c_std = std.c;
const mem = std.mem;
const Io = std.Io;
const Uri = std.Uri;
const fmt = std.fmt;
const json = std.json;
const heap = std.heap;
const http = std.http;
const debug = std.debug;
const Writer = Io.Writer;
const Queue = Io.Queue;
const HostName = Io.net.HostName;
const IpAddress = Io.net.IpAddress;
const LookupResult = Io.net.HostName.LookupResult;
const Client = http.Client;
const Scanner = json.Scanner;
const Allocator = mem.Allocator;
const FixedBufferAllocator = heap.FixedBufferAllocator;

const Store = @import("../data/Store.zig");
const constants = @import("../root.zig");
const Format = @import("../view/Format.zig");
const LogLine = @import("../view/LogLine.zig");
pub const HttpClient = @import("engine/HttpClient.zig");
pub const getPinnedConnection = HttpClient.getPinnedConnection;
pub const fetchApiToBuffer = HttpClient.fetchApiToBuffer;
pub const performLogin = HttpClient.performLogin;
pub const performLogout = HttpClient.performLogout;
pub const LocalLog = @import("engine/LocalLog.zig");
pub const streamFromFile = LocalLog.streamFromFile;
const Network = @import("Network.zig");
const NetworkProbe = @import("NetworkProbe.zig");
const Json = @import("parser/Json.zig");

pub fn isIpAddress(host: []const u8) bool {
    return Network.isIpAddress(host);
}

pub fn resolveTargetIp(io: Io, target_url: []const u8) !void {
    if (Store.dns_resolve_len > 0) return;
    const uri = try Uri.parse(target_url);
    const host = uri.host orelse return error.InvalidUrl;
    const port = uri.port orelse (if (mem.eql(u8, uri.scheme, "https")) @as(u16, 443) else @as(u16, 80));
    var host_buf: [HostName.max_len]u8 = undefined;
    const host_str = try host.toRaw(&host_buf);
    if (Network.isIpAddress(host_str)) {
        if (Store.debug_mode) {
            debug.print("\x1b[90m[DEBUG]\x1b[0m Target is already IP: {s}\n", .{host_str});
        }
        const dns_msg = try fmt.bufPrintZ(&Store.dns_resolve_str, "{s}", .{host_str});
        Store.dns_resolve_len = dns_msg.len;
        return;
    }
    const ip_res = try resolveHostToIp(io, host_str, port);
    var ip_buf: [64]u8 = undefined;
    var ip_w = Writer.fixed(&ip_buf);
    try ip_res.format(&ip_w);
    const ip_str = ip_w.buffered();
    if (Store.debug_mode) {
        debug.print("\x1b[90m[DEBUG]\x1b[0m Resolved {s} to {s}\n", .{ host_str, ip_str });
    }
    const dns_host_res = try fmt.bufPrintZ(&Store.dns_resolve_host, "{s}", .{host_str});
    Store.dns_resolve_host_len = dns_host_res.len;
    const dns_msg = try fmt.bufPrintZ(&Store.dns_resolve_str, "{s}", .{ip_str});
    Store.dns_resolve_len = dns_msg.len;
}

pub fn resolveHostToIp(io: Io, host: []const u8, port: u16) !IpAddress {
    if (IpAddress.parse(host, port)) |ip| return ip else |_| {}
    const host_name = try HostName.init(host);
    var queue_buf: [16]LookupResult = undefined;
    var queue = Queue(LookupResult).init(&queue_buf);
    try host_name.lookup(io, &queue, .{ .port = port });
    while (true) {
        const result = queue.getOneUncancelable(io) catch |err| {
            if (err == error.Closed) return error.HostNotFound;
            return err;
        };
        switch (result) {
            .address => |addr| return addr,
            .canonical_name => continue,
        }
    }
}

pub fn findFirstReachableUrl(io: Io, urls: [][]const u8) ![]const u8 {
    var probe_scratch: [65536]u8 align(16) = undefined;
    var fba = FixedBufferAllocator.init(&probe_scratch);
    const alloc = fba.allocator();
    for (urls) |url| {
        if (Store.should_exit) return error.OperationAborted;
        Store.pinned_identity_len = 0;
        if (Store.debug_mode) {
            debug.print("\x1b[90m[DEBUG]\x1b[0m Probing reachability: {s}\n", .{url});
        }
        fba.reset();
        var task = NetworkProbe.ProbeTask{
            .allocator = alloc,
            .io = io,
            .target_url = url,
            .dns_strategy = .local,
            .debug = Store.debug_mode,
        };
        const result = task.execute() catch |err| {
            if (Store.debug_mode) {
                debug.print("\x1b[91m[DEBUG]\x1b[0m Probe failed for {s}: {any}\n", .{ url, err });
            }
            continue;
        };
        if (Store.debug_mode) {
            debug.print("\x1b[92m[DEBUG]\x1b[0m URL confirmed reachable and valid: {s} (Status: {d})\n", .{ url, @intFromEnum(result.status) });
        }
        if (result.pinned_identity) |id| {
            const safe_len = @min(id.len, Store.pinned_identity.len);
            @memcpy(Store.pinned_identity[0..safe_len], id[0..safe_len]);
            Store.pinned_identity_len = safe_len;
        }
        if (result.resolved_ip) |ip| {
            const uri = Uri.parse(url) catch unreachable;
            var h_buf: [HostName.max_len]u8 = undefined;
            const hostname = uri.host orelse unreachable;
            const hostname_str = try hostname.toRaw(&h_buf);
            const dns_host_res = try fmt.bufPrintZ(&Store.dns_resolve_host, "{s}", .{hostname_str});
            Store.dns_resolve_host_len = dns_host_res.len;
            const dns_msg = try fmt.bufPrintZ(&Store.dns_resolve_str, "{s}", .{ip});
            Store.dns_resolve_len = dns_msg.len;
        }
        return url;
    }
    return error.NoReachableUrl;
}

pub fn fetchClientMap(_: Allocator, client: *Client, endpoint: []const u8) !void {
    const io = client.io;
    const body = try fetchApiToBuffer(client, endpoint, "", Store.scratch_buffer);
    var scanner = Scanner.initCompleteInput(Store.allocator, body);
    defer scanner.deinit();
    if ((try scanner.next()) != .object_begin) return;
    Store.state_lock.lockUncancelable(io);
    defer Store.state_lock.unlock(io);
    Store.client_count = 0;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        if (mem.eql(u8, token.string, "clients")) {
            if ((try scanner.next()) != .array_begin) break;
            while ((try scanner.peekNextTokenType()) != .array_end) {
                if ((try scanner.next()) != .object_begin) break;
                var name: []const u8 = "unknown";
                var first_tag: []const u8 = "";
                while (true) {
                    const field_t = try scanner.next();
                    if (field_t == .object_end) break;
                    const key = field_t.string;
                    if (mem.eql(u8, key, "name")) {
                        name = (try scanner.next()).string;
                    } else if (mem.eql(u8, key, "tags")) {
                        const h = scanner.stackHeight();
                        if ((try scanner.next()) == .array_begin) {
                            if ((try scanner.peekNextTokenType()) == .string) {
                                first_tag = (try scanner.next()).string;
                            }
                            try scanner.skipUntilStackHeight(h);
                        }
                    } else if (mem.eql(u8, key, "ids")) {
                        if ((try scanner.next()) == .array_begin) {
                            while ((try scanner.peekNextTokenType()) == .string) {
                                const id = (try scanner.next()).string;
                                if (Store.client_count < constants.MAX_CLIENTS) {
                                    var entry = &Store.client_entries[Store.client_count];
                                    const ip_len = @min(id.len, entry.ip.len);
                                    @memcpy(entry.ip[0..ip_len], id[0..ip_len]);
                                    entry.ip_len = @intCast(ip_len);
                                    const name_len = @min(name.len, entry.name.len);
                                    @memcpy(entry.name[0..name_len], name[0..name_len]);
                                    entry.name_len = @intCast(name_len);
                                    const tag_len = @min(first_tag.len, entry.tags.len);
                                    @memcpy(entry.tags[0..tag_len], first_tag[0..tag_len]);
                                    entry.tags_len = @intCast(tag_len);
                                    Store.client_count += 1;
                                }
                            }
                            _ = try scanner.next();
                        }
                    } else {
                        try scanner.skipValue();
                    }
                }
            }
            _ = try scanner.next();
        } else {
            try scanner.skipValue();
        }
    }
}
