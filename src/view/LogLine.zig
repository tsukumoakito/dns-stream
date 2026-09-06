const std = @import("std");
const Io = std.Io;
const fmt = std.fmt;
const mem = std.mem;
const File = Io.File;
const Writer = Io.Writer;
const Terminal = Io.Terminal;
const Allocator = mem.Allocator;

const constants = @import("dns_stream");

const Store = @import("../data/Store.zig");
const Dns = @import("../logic/parser/Dns.zig");
const Json = @import("../logic/parser/Json.zig");
const Format = @import("Format.zig");

const reason_names = [_][]const u8{
    "NotFilteredNotFound",
    "NotFilteredWhiteList",
    "NotFilteredError",
    "FilteredBlackList",
    "FilteredSafeBrowsing",
    "FilteredParental",
    "FilteredInvalid",
    "FilteredSafeSearch",
    "FilteredBlockedService",
    "Rewrite",
    "RewriteEtcHosts",
    "RewriteRule",
};

pub fn printHeader(io: Io, w: File, width: u16, no_color: bool) !void {
    const w_time_total: usize = 15;
    const w_client_raw: usize = 28;
    const w_domain_raw: usize = 40;
    const w_status_raw: usize = 20;
    const w_upstream_raw: usize = 20;
    const used_width_for_dest = 13 + 28 + 40 + 20 + 20 + 15;
    const w_dest_raw = if (width > used_width_for_dest) width - used_width_for_dest else 30;
    const col_time: usize = w_time_total;
    const col_client: usize = w_client_raw + 3;
    const col_domain: usize = w_domain_raw + 3;
    const col_dest: usize = w_dest_raw + 1;
    const col_status: usize = w_status_raw + 1;
    const col_upstream: usize = w_upstream_raw;
    Store.io_mutex.lockUncancelable(io);
    defer Store.io_mutex.unlock(io);
    var f_w_buf: [4096]u8 = undefined;
    var writer = Writer.fixed(&f_w_buf);
    const b_bold = if (no_color) "" else Format.clr_blue_bold;
    const reset = if (no_color) "" else Format.clr_reset;
    const dim = if (no_color) "" else Format.clr_dim;
    try writer.writeAll("\n");
    try writer.writeAll(b_bold);
    const headers = [_]struct { n: []const u8, w: usize }{
        .{ .n = "TIME", .w = col_time },
        .{ .n = "CLIENT (DEVICE)", .w = col_client },
        .{ .n = "DOMAIN", .w = col_domain },
        .{ .n = "DEST IP", .w = col_dest },
        .{ .n = "STATUS", .w = col_status },
        .{ .n = "UPSTREAM", .w = col_upstream },
    };
    inline for (headers) |h| {
        try writer.writeAll(h.n);
        if (h.n.len < h.w) try writer.splatByteAll(' ', h.w - h.n.len);
    }
    try writer.writeAll("\n");
    try writer.writeAll(reset);
    try writer.writeAll(dim);
    try writer.splatByteAll('-', width);
    try writer.writeAll(reset);
    try writer.writeAll("\n");
    try w.writeStreamingAll(io, writer.buffered());
}

pub fn displayLogItemRaw(
    terminal: *Terminal,
    io: Io,
    allocator: Allocator,
    json_input: []const u8,
    term_w: u16,
    w: File,
    is_api: bool,
    no_color: bool,
) !void {
    _ = terminal;
    _ = allocator;
    const full_t = Json.getCompatibleValue(json_input, .time) orelse return;
    const domain_raw = Json.getCompatibleValue(json_input, .domain) orelse "unknown";
    const ip = Json.getCompatibleValue(json_input, .client) orelse "unknown";
    var log_id_buf: [192]u8 = undefined;
    const log_id = fmt.bufPrint(&log_id_buf, "{s}_{s}_{s}", .{ full_t, domain_raw, ip }) catch log_id_buf[0..0];
    Store.state_lock.lockSharedUncancelable(io);
    if (Store.seen_buffer.exists(log_id)) {
        Store.state_lock.unlockShared(io);
        return;
    }
    var name_raw: []const u8 = Store.getClientName(ip);
    if (is_api) {
        if (Json.getJsonValueRaw(json_input, "client_info")) |ci| {
            if (Json.getJsonValueRaw(ci, "name")) |n| name_raw = n;
        }
    }
    var name_buf: [128]u8 = undefined;
    var name_w = Writer.fixed(&name_buf);
    try Json.writeJsonUnescaped(&name_w, name_raw);
    const name = name_w.buffered();
    if (Store.filter_ips_count > 0 or Store.filter_names_count > 0) {
        var match = false;
        if (Store.filter_ips_count > 0) {
            for (Store.filter_ips[0..Store.filter_ips_count]) |*f| {
                const f_val = f.val[0..f.len];
                if (mem.endsWith(u8, f_val, "*")) {
                    if (mem.startsWith(u8, ip, f_val[0 .. f_val.len - 1])) {
                        match = true;
                        break;
                    }
                } else if (mem.eql(u8, ip, f_val)) {
                    match = true;
                    break;
                }
            }
        }
        if (!match and Store.filter_names_count > 0) {
            for (Store.filter_names[0..Store.filter_names_count]) |*f| {
                const f_val = f.val[0..f.len];
                if (name.len > 0 and mem.indexOf(u8, name, f_val) != null) {
                    match = true;
                    break;
                }
            }
        }
        if (!match) {
            Store.state_lock.unlockShared(io);
            return;
        }
    }
    Store.state_lock.unlockShared(io);
    Store.state_lock.lockUncancelable(io);
    Store.seen_buffer.add(log_id);
    Store.state_lock.unlock(io);
    var domain_buf: [256]u8 = undefined;
    var domain_w = Writer.fixed(&domain_buf);
    try Json.writeJsonUnescaped(&domain_w, domain_raw);
    const domain = domain_w.buffered();
    var dest_buf: [1024]u8 = undefined;
    var dest_writer = Writer.fixed(&dest_buf);
    const ans_raw = Json.getCompatibleValue(json_input, .answer);
    if (is_api) {
        if (ans_raw) |raw| {
            var i: usize = 0;
            var first_ans = true;
            while (i < raw.len) {
                const obj_start = mem.indexOfScalarPos(u8, raw, i, '{') orelse break;
                var depth: usize = 0;
                var obj_end = obj_start;
                while (obj_end < raw.len) : (obj_end += 1) {
                    const char = raw[obj_end];
                    if (char == '{') depth += 1 else if (char == '}') {
                        depth -= 1;
                        if (depth == 0) break;
                    }
                }
                if (obj_end >= raw.len) break;
                if (Json.getJsonValueRaw(raw[obj_start .. obj_end + 1], "value")) |val| {
                    if (!first_ans) try dest_writer.writeAll(" | ");
                    try Json.writeJsonUnescaped(&dest_writer, val);
                    first_ans = false;
                }
                i = obj_end + 1;
            }
        }
    } else {
        if (ans_raw) |ans_b64| {
            try Dns.decodeAndParseDnsAnswer(ans_b64, &dest_writer);
        }
    }
    const dest_display = if (dest_writer.buffered().len > 0) dest_writer.buffered() else "-";
    var display_status: []const u8 = "NotFilteredNotFound";
    if (is_api) {
        const reason = Json.getJsonValueRaw(json_input, "reason") orelse "";
        const status_raw = Json.getJsonValueRaw(json_input, "status") orelse "";
        if (reason.len > 0 and !mem.eql(u8, reason, "NotFilteredNotFound")) {
            display_status = reason;
        } else if (status_raw.len > 0 and !mem.eql(u8, status_raw, "NOERROR")) {
            display_status = status_raw;
        }
    } else {
        if (Json.getJsonValueRaw(json_input, "Result")) |res| {
            const reason_str = Json.getJsonValueRaw(res, "Reason") orelse "0";
            const reason_idx = fmt.parseInt(usize, reason_str, 10) catch @as(usize, 0);
            display_status = if (reason_idx < reason_names.len) reason_names[reason_idx] else "Processed";
        }
    }
    const is_blocked = mem.startsWith(u8, display_status, "Filtered") and mem.indexOf(u8, display_status, "WhiteList") == null;
    const is_rewrite = mem.startsWith(u8, display_status, "Rewrite") or mem.eql(u8, display_status, "FilteredSafeSearch");
    const is_whitelist = mem.indexOf(u8, display_status, "WhiteList") != null;
    const c_color = if (no_color) "" else Format.getIpColor(ip);
    const d_color = if (no_color) "" else (if (is_blocked) Format.clr_red else if (is_rewrite) Format.clr_cyan else Format.clr_bold);
    const s_color = if (no_color) "" else (if (is_blocked) Format.clr_red else if (is_rewrite) Format.clr_cyan else if (is_whitelist) Format.clr_green else Format.clr_bold);
    const dim = if (no_color) "" else Format.clr_dim;
    const reset = if (no_color) "" else Format.clr_reset;
    const yellow = if (no_color) "" else Format.clr_yellow;
    const is_cached = blk: {
        const c_val = Json.getCompatibleValue(json_input, .cached);
        break :blk (c_val != null and mem.eql(u8, c_val.?, "true"));
    };
    const upstream_raw = Json.getCompatibleValue(json_input, .upstream);
    const upstream_base = if (upstream_raw != null and upstream_raw.?.len > 0) upstream_raw.? else "-";
    const time_str = if (full_t.len >= 23) full_t[11..23] else if (full_t.len >= 19) full_t[11..19] else "??:??:??";
    const w_time: usize = 13;
    const w_client: usize = 28;
    const w_domain: usize = 40;
    const w_status: usize = 20;
    const w_upstream: usize = 20;
    const used_width = w_time + w_client + w_domain + w_status + w_upstream + 15;
    const w_dest = if (term_w > used_width) term_w - used_width else 30;
    const d_lines = Format.wrapText(domain, w_domain, " -.,;|");
    const dest_lines = Format.wrapText(dest_display, w_dest, " -,;|");
    const max_rows = @max(d_lines.len, dest_lines.len);
    var f_w_buf: [8192]u8 = undefined;
    var writer = Writer.fixed(&f_w_buf);
    var r: usize = 0;
    while (r < max_rows) : (r += 1) {
        if (r == 0) {
            try writer.writeAll(dim);
            try writer.writeAll("[");
            try writer.writeAll(time_str);
            try writer.writeAll("]");
            try writer.writeAll(reset);
            try writer.writeAll(" ");
            try writer.writeAll(c_color);
            try writer.writeAll(ip);
            var current_client_w = ip.len;
            if (name.len > 0) {
                try writer.writeAll(" (");
                try writer.writeAll(name);
                try writer.writeAll(")");
                current_client_w += name.len + 3;
            }
            if (current_client_w < w_client) try writer.splatByteAll(' ', w_client - current_client_w);
            try writer.writeAll(reset);
            try writer.writeAll(" ");
            try writer.writeAll(dim);
            try writer.writeAll("→");
            try writer.writeAll(reset);
            try writer.writeAll(" ");
            try writer.writeAll(d_color);
            const d_line0 = d_lines.lines[0];
            try writer.writeAll(d_line0);
            if (d_line0.len < w_domain) try writer.splatByteAll(' ', w_domain - d_line0.len);
            try writer.writeAll(reset);
            try writer.writeAll(dim);
            try writer.writeAll(" → ");
            try writer.writeAll(reset);
            try writer.writeAll(yellow);
            const dst_line0 = dest_lines.lines[0];
            try writer.writeAll(dst_line0);
            if (dst_line0.len < w_dest) try writer.splatByteAll(' ', w_dest - dst_line0.len);
            try writer.writeAll(reset);
            try writer.writeAll(" ");
            try writer.writeAll(s_color);
            try writer.writeAll(display_status);
            if (display_status.len < w_status) try writer.splatByteAll(' ', w_status - display_status.len);
            try writer.writeAll(reset);
            try writer.writeAll(" ");
            try writer.writeAll(dim);
            try writer.writeAll(upstream_base);
            var current_up_w = upstream_base.len;
            if (is_cached) {
                try writer.writeAll(" [C]");
                current_up_w += 4;
            }
            if (current_up_w < w_upstream) try writer.splatByteAll(' ', w_upstream - current_up_w);
            try writer.writeAll(reset);
            try writer.writeAll("\n");
        } else {
            try writer.splatByteAll(' ', 49 + 1);
            try writer.writeAll(d_color);
            const d_line = if (r < d_lines.len) d_lines.lines[r] else "";
            try writer.writeAll(d_line);
            if (d_line.len < w_domain) try writer.splatByteAll(' ', w_domain - d_line.len);
            try writer.writeAll(reset);
            try writer.writeAll(dim);
            try writer.writeAll("   ");
            try writer.writeAll(reset);
            try writer.writeAll(yellow);
            const dst_line = if (r < dest_lines.len) dest_lines.lines[r] else "";
            try writer.writeAll(dst_line);
            if (dst_line.len < w_dest) try writer.splatByteAll(' ', w_dest - dst_line.len);
            try writer.writeAll(reset);
            try writer.writeAll("\n");
        }
    }
    Store.io_mutex.lockUncancelable(io);
    defer Store.io_mutex.unlock(io);
    try w.writeStreamingAll(io, writer.buffered());
}
