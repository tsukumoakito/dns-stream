const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const heap = std.heap;
const math = std.math;
const hash = std.hash;
const crypto = std.crypto;
const File = Io.File;
const Mutex = Io.Mutex;
const RwLock = Io.RwLock;
const Writer = Io.Writer;
const Allocator = mem.Allocator;
const FixedBufferAllocator = heap.FixedBufferAllocator;

const Collector = @import("../core/terminal/Collector.zig");
const constants = @import("../root.zig");

pub var should_exit: bool = false;
pub var debug_mode: bool = false;

pub var io_mutex: Mutex = .init;
pub var state_lock: RwLock = .init;

pub var scratch_fba: FixedBufferAllocator = undefined;
pub var scratch_buffer: []u8 = undefined;
pub var net_client_fba: FixedBufferAllocator = undefined;
pub var net_req_fba: FixedBufferAllocator = undefined;

pub var querylog_mmap: ?File.MemoryMap = null;
pub var log_content_hash: u64 = 0;

pub const ProxyType = enum { none, socks5, http, https, auto };
pub var proxy_type: ProxyType = .auto;
pub var proxy_url: [512]u8 = [_]u8{0} ** 512;
pub var proxy_url_len: usize = 0;

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

pub var pinned_identity: [256]u8 = [_]u8{0} ** 256;
pub var pinned_identity_len: usize = 0;
pub var dns_resolve_host: [160]u8 = [_]u8{0} ** 160;
pub var dns_resolve_host_len: usize = 0;
pub var dns_resolve_str: [160]u8 = [_]u8{0} ** 160;
pub var dns_resolve_len: usize = 0;
pub var local_offset: i64 = 0;

pub var session_cookie: [256]u8 = [_]u8{0} ** 256;
pub var session_cookie_len: usize = 0;
pub var old_session_cookie: [256]u8 = [_]u8{0} ** 256;
pub var old_session_cookie_len: usize = 0;

pub const AbandonedSession = struct {
    cookie: [256]u8 = [_]u8{0} ** 256,
    len: usize = 0,
};

pub var session_trash: [16]AbandonedSession = undefined;
pub var session_trash_count: usize = 0;

pub var user_agent: [64]u8 = [_]u8{0} ** 64;
pub var user_agent_len: usize = 0;
pub var last_seen_ts: [48]u8 = [_]u8{0} ** 48;
pub var last_seen_ts_len: usize = 0;

pub var session_start_anchor: [48]u8 = [_]u8{0} ** 48;
pub var session_start_anchor_len: usize = 0;
pub var custom_end_ts: [48]u8 = [_]u8{0} ** 48;
pub var custom_end_ts_len: usize = 0;
pub var has_drawn_boundary: bool = false;

pub var is_footer_fixed: bool = false;
pub var footer_height: u16 = 0;
pub var initial_cursor_row: u16 = 1;
pub var current_total_rows: u16 = 0;

pub var formatSize: *const fn (buf: []u8, bytes: usize) []const u8 = fallbackFormatSize;

pub const SeenBuffer = struct {
    ids: [][128]u8 = &.{},
    lens: []u8 = &.{},
    hashes: []u64 = &.{},
    table: []u32 = &.{},
    mask: usize = 0,
    capacity: usize = 0,
    cursor: usize = 0,

    pub fn deinit(self: *@This(), alloc: Allocator) void {
        if (self.capacity == 0) return;
        alloc.free(self.ids);
        alloc.free(self.lens);
        alloc.free(self.hashes);
        alloc.free(self.table);
        self.* = .{};
    }

    inline fn getHash(data: []const u8) u64 {
        return hash.Wyhash.hash(0, data);
    }

    pub fn init(alloc: Allocator, capacity: usize) !SeenBuffer {
        const table_size = math.ceilPowerOfTwo(usize, capacity * 4) catch capacity * 4;
        return SeenBuffer{
            .ids = try alloc.alloc([128]u8, capacity),
            .lens = try alloc.alloc(u8, capacity),
            .hashes = try alloc.alloc(u64, capacity),
            .table = try alloc.alloc(u32, table_size),
            .mask = table_size - 1,
            .capacity = capacity,
        };
    }

    pub fn add(self: *@This(), id: []const u8) void {
        if (self.capacity == 0) return;
        const h = getHash(id);
        const idx = self.cursor;
        if (self.lens[idx] > 0) self.removeFromTable(idx);
        const safe_len = @min(id.len, 128);
        @memcpy(self.ids[idx][0..safe_len], id[0..safe_len]);
        self.lens[idx] = @intCast(safe_len);
        self.hashes[idx] = h;
        var pos = h & self.mask;
        while (self.table[pos] != 0) {
            pos = (pos + 1) & self.mask;
        }
        self.table[pos] = @intCast(idx + 1);
        self.cursor = (self.cursor + 1) % self.capacity;
    }

    pub fn exists(self: *const @This(), id: []const u8) bool {
        if (self.capacity == 0) return false;
        const h = getHash(id);
        var pos = h & self.mask;
        while (self.table[pos] != 0) {
            const idx = self.table[pos] - 1;
            if (self.hashes[idx] == h and self.lens[idx] == id.len and
                mem.eql(u8, self.ids[idx][0..id.len], id)) return true;
            pos = (pos + 1) & self.mask;
        }
        return false;
    }

    fn removeFromTable(self: *@This(), target_idx: usize) void {
        const h = self.hashes[target_idx];
        var pos = h & self.mask;
        while (self.table[pos] != target_idx + 1) {
            pos = (pos + 1) & self.mask;
        }
        self.table[pos] = 0;
        var next = (pos + 1) & self.mask;
        while (self.table[next] != 0) {
            const temp_idx = self.table[next] - 1;
            const ideal_pos = self.hashes[temp_idx] & self.mask;
            const is_displaced = if (next >= pos)
                (ideal_pos <= pos or ideal_pos > next)
            else
                (ideal_pos <= pos and ideal_pos > next);
            if (is_displaced) {
                self.table[pos] = self.table[next];
                self.table[next] = 0;
                pos = next;
            }
            next = (next + 1) & self.mask;
        }
    }

    pub fn clear(self: *@This()) void {
        if (self.capacity == 0) return;
        @memset(self.lens, 0);
        @memset(self.table, 0);
        self.cursor = 0;
    }
};

pub const ClientEntry = struct {
    ip: [45]u8 = [_]u8{0} ** 45,
    ip_len: u8 = 0,
    cid: [64]u8 = [_]u8{0} ** 64,
    cid_len: u8 = 0,
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    tags: [64]u8 = [_]u8{0} ** 64,
    tags_len: u8 = 0,
};

pub const FilterEntry = struct {
    val: [64]u8 = [_]u8{0} ** 64,
    len: u8 = 0,
};

pub const ColorRule = struct {
    pattern: [45]u8 = [_]u8{0} ** 45,
    pattern_len: u8 = 0,
    color_code: []const u8 = "",
};

pub var seen_buffer: SeenBuffer = .{};
pub var client_entries: [constants.MAX_CLIENTS]ClientEntry = undefined;
pub var client_count: usize = 0;
pub var filter_ips: [constants.MAX_FILTERS]FilterEntry = undefined;
pub var filter_ips_count: usize = 0;
pub var filter_names: [constants.MAX_FILTERS]FilterEntry = undefined;
pub var filter_names_count: usize = 0;

pub var ip_color_rules: [constants.MAX_COLOR_RULES]ColorRule = undefined;
pub var ip_color_rules_count: usize = 0;

pub var allocator: Allocator = undefined;
pub const keyring_key_name = "dns-stream-auth-key";

pub fn init(io: Io, base_allocator: Allocator, scratch_buf: []u8, net_client_raw_buf: []u8, net_req_raw_buf: []u8, max_seen: usize) void {
    allocator = base_allocator;
    scratch_fba = FixedBufferAllocator.init(scratch_buf);
    scratch_buffer = scratch_buf;
    net_client_fba = FixedBufferAllocator.init(net_client_raw_buf);
    net_req_fba = FixedBufferAllocator.init(net_req_raw_buf);
    seen_buffer = SeenBuffer.init(base_allocator, max_seen) catch
        SeenBuffer.init(base_allocator, constants.DEFAULT_MAX_SEEN) catch
        SeenBuffer{};
    seen_buffer.clear();
    client_count = 0;
    session_cookie_len = 0;
    session_trash_count = 0;
    dns_resolve_len = 0;
    dns_resolve_host_len = 0;
    last_seen_ts_len = 0;
    proxy_type = .auto;
    proxy_url_len = 0;
    session_start_anchor_len = 0;
    custom_end_ts_len = 0;
    has_drawn_boundary = false;
    is_footer_fixed = false;
    footer_height = 0;
    initial_cursor_row = 1;
    current_total_rows = 0;
    debug_mode = false;
    log_content_hash = 0;
    var random_bytes: [8]u8 = undefined;
    Io.randomSecure(io, &random_bytes) catch {
        @memset(&random_bytes, 0);
    };
    var hex_array: [16]u8 = undefined;
    var hex_w = Writer.fixed(&hex_array);
    hex_w.print("{x:0>16}", .{mem.readInt(u64, &random_bytes, .little)}) catch {};
    const ua_res = fmt.bufPrintZ(&user_agent, "DNS-Stream-Monitor/{s}", .{hex_w.buffered()}) catch "DNS-Stream-Monitor/1.0";
    user_agent_len = ua_res.len;
}

pub fn deinit(io: Io) void {
    seen_buffer.deinit(allocator);
    if (querylog_mmap) |*m| m.destroy(io);
    crypto.secureZero(u8, &session_cookie);
    crypto.secureZero(u8, &old_session_cookie);
    for (&session_trash) |*s| {
        crypto.secureZero(u8, &s.cookie);
    }
    crypto.secureZero(u8, &pinned_identity);
}

pub fn getCustomColor(ip: []const u8) ?[]const u8 {
    if (ip_color_rules_count == 0) return null;
    const count = ip_color_rules_count;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const rule = &ip_color_rules[i];
        const pattern = rule.pattern[0..rule.pattern_len];
        if (mem.eql(u8, pattern, ip)) return rule.color_code;
        if (mem.endsWith(u8, pattern, "*")) {
            const prefix = pattern[0 .. pattern.len - 1];
            if (mem.startsWith(u8, ip, prefix)) return rule.color_code;
        }
    }
    return null;
}

pub fn getClientName(ip: []const u8) []const u8 {
    const count = client_count;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const entry = &client_entries[i];
        if (entry.ip_len == ip.len and mem.eql(u8, entry.ip[0..entry.ip_len], ip)) {
            return entry.name[0..entry.name_len];
        }
    }
    return "";
}

pub fn getClientNameById(cid: []const u8) []const u8 {
    const count = client_count;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const entry = &client_entries[i];
        if (entry.cid_len == cid.len and mem.eql(u8, entry.cid[0..entry.cid_len], cid)) {
            return entry.name[0..entry.name_len];
        }
    }
    return "";
}

fn fallbackFormatSize(buf: []u8, bytes: usize) []const u8 {
    var f = Writer.fixed(buf);
    f.print("{d} B", .{bytes}) catch {};
    return f.buffered();
}

pub fn appendDiagnosticStats(ui_collector: *Collector, diag: anytype) !void {
    const seen_count = if (seen_buffer.capacity > 0 and seen_buffer.lens[seen_buffer.capacity - 1] > 0) seen_buffer.capacity else seen_buffer.cursor;
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "Seen Buffer Fill", seen_count, seen_buffer.capacity, " IDs");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "Client Cache", client_count, constants.MAX_CLIENTS, " clients");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "IP Filters", filter_ips_count, constants.MAX_FILTERS, " rules");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "Name Filters", filter_names_count, constants.MAX_FILTERS, " rules");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "IP Color Rules", ip_color_rules_count, constants.MAX_COLOR_RULES, " rules");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "Net Client FBA", net_client_fba.end_index, net_client_fba.buffer.len, "");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "Net Request FBA", net_req_fba.end_index, net_req_fba.buffer.len, "");
    try diag.appendStatRow(ui_collector.terminal, ui_collector, "Session Trash", session_trash_count, 16, " items");
}
