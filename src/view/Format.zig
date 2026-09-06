const std = @import("std");
const Io = std.Io;
const net = Io.net;
const mem = std.mem;
const time = std.time;
const ascii = std.ascii;
const Clock = Io.Clock;
const IpAddress = Io.net.IpAddress;
const EpochSeconds = time.epoch.EpochSeconds;
const StaticStringMap = std.StaticStringMap;

const Store = @import("../data/Store.zig");

pub const clr_reset = "\x1b[0m";
pub const clr_dim = "\x1b[2m";
pub const clr_bold = "\x1b[1m";
pub const clr_cyan = "\x1b[96m";
pub const clr_red = "\x1b[91m";
pub const clr_green = "\x1b[92m";
pub const clr_blue_bold = "\x1b[1;34m";
pub const clr_yellow = "\x1b[93m";
pub const clr_gray = "\x1b[90m";
pub const clr_blue = "\x1b[94m";
pub const clr_magenta = "\x1b[95m";
pub const clr_white_bg_red = "\x1b[41;97m";

pub fn getColorCode(name: []const u8) []const u8 {
    const color_map = StaticStringMap([]const u8).initComptime(.{
        .{ "reset", clr_reset },
        .{ "dim", clr_dim },
        .{ "bold", clr_bold },
        .{ "cyan", clr_cyan },
        .{ "red", clr_red },
        .{ "green", clr_green },
        .{ "yellow", clr_yellow },
        .{ "gray", clr_gray },
        .{ "blue", clr_blue },
        .{ "magenta", clr_magenta },
    });
    return color_map.get(name) orelse clr_bold;
}

pub fn getIpColor(ip: []const u8) []const u8 {
    if (Store.getCustomColor(ip)) |code| {
        return code;
    }
    const addr = IpAddress.parse(ip, 0) catch return clr_bold;
    switch (addr) {
        .ip4 => |ip4| {
            const b = ip4.bytes;
            if (b[0] == 127) {
                if (b[1] == 0 and b[2] == 0 and b[3] == 1) return clr_gray;
                return clr_dim;
            }
            if (b[0] == 10) {
                if (b[1] == 0) return clr_green;
                if (b[1] == 200) return clr_yellow;
            }
            if (b[0] == 192 and b[1] == 168) {
                if (b[2] == 0) return clr_cyan;
                return clr_blue;
            }
        },
        .ip6 => |ip6| {
            if (ip6.isLoopBack()) return clr_gray;
        },
    }
    return clr_bold;
}

pub fn writeUint(buf: []u8, val: u64) usize {
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    var v = val;
    var tmp: [20]u8 = undefined;
    var i: usize = 20;
    while (v > 0) {
        i -= 1;
        tmp[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    const len = 20 - i;
    @memcpy(buf[0..len], tmp[i..20]);
    return len;
}

pub fn writeUintPadded(buf: []u8, val: u64, width: usize) usize {
    var tmp: [20]u8 = undefined;
    const digit_len = writeUint(&tmp, val);
    const pad = if (width > digit_len) width - digit_len else 0;
    @memset(buf[0..pad], ' ');
    @memcpy(buf[pad .. pad + digit_len], tmp[0..digit_len]);
    return pad + digit_len;
}

pub inline fn writeHex2(buf: []u8, val: u8) void {
    const charset = "0123456789abcdef";
    buf[0] = charset[val >> 4];
    buf[1] = charset[val & 0xf];
}

fn writeUintFixed(buf: []u8, val: u64, width: usize) void {
    var v = val;
    var i: usize = width;
    while (i > 0) {
        i -= 1;
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
}

pub const WrappedResult = struct {
    lines: [5][]const u8 = [_][]const u8{""} ** 5,
    len: usize = 0,
};

pub fn wrapText(text: []const u8, width_in: usize, delims: []const u8) WrappedResult {
    var res = WrappedResult{};
    if (text.len == 0) return res;
    const width = @max(width_in, 1);
    var start: usize = 0;
    while (start < text.len and res.len < 5) {
        const remaining = text.len - start;
        if (remaining <= width) {
            res.lines[res.len] = text[start..];
            res.len += 1;
            break;
        }
        const end = start + width;
        var found_delim: ?usize = null;
        var j: usize = end;
        while (j > start) : (j -= 1) {
            if (mem.indexOfScalar(u8, delims, text[j - 1]) != null) {
                found_delim = j;
                break;
            }
        }
        const actual_end = found_delim orelse end;
        res.lines[res.len] = text[start..actual_end];
        res.len += 1;
        start = actual_end;
        if (start < text.len and text[start] == ' ') start += 1;
    }
    return res;
}

pub fn isExcessiveFuture(io: Io, ts_str: []const u8) bool {
    if (ts_str.len < 19) return false;
    const now_local_with_grace = Clock.real.now(io).toSeconds() + Store.local_offset + 300;
    const e_val = EpochSeconds{ .secs = @intCast(now_local_with_grace) };
    const yd = e_val.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = e_val.getDaySeconds();
    var compare_buf: [19]u8 = undefined;
    writeUintFixed(compare_buf[0..4], yd.year, 4);
    compare_buf[4] = '-';
    writeUintFixed(compare_buf[5..7], md.month.numeric(), 2);
    compare_buf[7] = '-';
    writeUintFixed(compare_buf[8..10], md.day_index + 1, 2);
    compare_buf[10] = 'T';
    writeUintFixed(compare_buf[11..13], ds.getHoursIntoDay(), 2);
    compare_buf[13] = ':';
    writeUintFixed(compare_buf[14..16], ds.getMinutesIntoHour(), 2);
    compare_buf[16] = ':';
    writeUintFixed(compare_buf[17..19], ds.getSecondsIntoMinute(), 2);
    return mem.order(u8, ts_str[0..19], &compare_buf) == .gt;
}

pub fn formatUnixToLocalRfc3339(buf: []u8, ts: i64, offset: i64, suffix: []const u8) ![]const u8 {
    const local_ts = ts + offset;
    const e_val = EpochSeconds{ .secs = @intCast(local_ts) };
    const ds = e_val.getDaySeconds();
    const yd = e_val.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    writeUintFixed(buf[0..4], yd.year, 4);
    buf[4] = '-';
    writeUintFixed(buf[5..7], md.month.numeric(), 2);
    buf[7] = '-';
    writeUintFixed(buf[8..10], md.day_index + 1, 2);
    buf[10] = 'T';
    writeUintFixed(buf[11..13], ds.getHoursIntoDay(), 2);
    buf[13] = ':';
    writeUintFixed(buf[14..16], ds.getMinutesIntoHour(), 2);
    buf[16] = ':';
    writeUintFixed(buf[17..19], ds.getSecondsIntoMinute(), 2);
    @memcpy(buf[19..29], ".000000000");
    @memcpy(buf[29 .. 29 + suffix.len], suffix);
    return buf[0 .. 29 + suffix.len];
}

pub fn parseFuzzyTimestamp(input: []const u8, out_buf: []u8, tz_suffix: []const u8) ![]const u8 {
    var digits: [23]u8 = [_]u8{'0'} ** 23;
    digits[4] = '0';
    digits[5] = '1';
    digits[6] = '0';
    digits[7] = '1';
    var d_idx: usize = 0;
    for (input) |c| {
        if (ascii.isDigit(c)) {
            if (d_idx < 23) {
                digits[d_idx] = c;
                d_idx += 1;
            }
        }
    }
    if (d_idx < 4) return error.InvalidYearFormat;
    @memcpy(out_buf[0..4], digits[0..4]);
    out_buf[4] = '-';
    @memcpy(out_buf[5..7], digits[4..6]);
    out_buf[7] = '-';
    @memcpy(out_buf[8..10], digits[6..8]);
    out_buf[10] = 'T';
    @memcpy(out_buf[11..13], digits[8..10]);
    out_buf[13] = ':';
    @memcpy(out_buf[14..16], digits[10..12]);
    out_buf[16] = ':';
    @memcpy(out_buf[17..19], digits[12..14]);
    out_buf[19] = '.';
    @memcpy(out_buf[20..29], digits[14..23]);
    @memcpy(out_buf[29 .. 29 + tz_suffix.len], tz_suffix);
    return out_buf[0 .. 29 + tz_suffix.len];
}
