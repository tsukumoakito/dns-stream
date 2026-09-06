const std = @import("std");
const Io = std.Io;
const fmt = std.fmt;
const mem = std.mem;
const http = std.http;
const crypto = std.crypto;
const json = std.json;
const Scanner = json.Scanner;
const Clock = Io.Clock;
const Client = http.Client;
const Allocator = mem.Allocator;

const Store = @import("../data/Store.zig");
const Engine = @import("../logic/Engine.zig");
const Json = @import("../logic/parser/Json.zig");
const Format = @import("../view/Format.zig");
const Config = @import("Config.zig");

pub fn initialize(
    io: Io,
    allocator: Allocator,
    http_client: *Client,
    config: *Config.AppConfig,
    final_url: []const u8,
) !struct { session_start: []const u8, effective_start: []const u8, suffix: []const u8 } {
    const tz_res = blk: {
        var q_url_buf: [512]u8 = undefined;
        const q_endpoint = try fmt.bufPrint(&q_url_buf, "{s}/querylog?limit=1", .{final_url});
        break :blk try getLogTimezone(http_client, q_endpoint);
    };
    Store.local_offset = if (config.time_offset != 0) config.time_offset else tz_res.offset;
    const session_start_ts = getActualUserSessionStart(io);
    var boot_ts_buf: [128]u8 = undefined;
    const session_start_ts_str = try Format.formatUnixToLocalRfc3339(&boot_ts_buf, session_start_ts, Store.local_offset, tz_res.suffix);
    const anchor_len = @min(session_start_ts_str.len, Store.session_start_anchor.len);
    @memcpy(Store.session_start_anchor[0..anchor_len], session_start_ts_str[0..anchor_len]);
    Store.session_start_anchor_len = anchor_len;
    var final_start_ts_buf: [128]u8 = undefined;
    const effective_start_ts = if (config.start_time) |st|
        try Format.parseFuzzyTimestamp(st, &final_start_ts_buf, tz_res.suffix)
    else
        session_start_ts_str;
    if (config.end_time) |et| {
        const et_str = try Format.parseFuzzyTimestamp(et, &Store.custom_end_ts, tz_res.suffix);
        Store.custom_end_ts_len = et_str.len;
    }
    const safe_seen_len = @min(effective_start_ts.len, Store.last_seen_ts.len);
    @memcpy(Store.last_seen_ts[0..safe_seen_len], effective_start_ts[0..safe_seen_len]);
    Store.last_seen_ts_len = safe_seen_len;
    return .{
        .session_start = try allocator.dupe(u8, session_start_ts_str),
        .effective_start = try allocator.dupe(u8, effective_start_ts),
        .suffix = try allocator.dupe(u8, tz_res.suffix),
    };
}

pub fn terminate(io: Io, client: *Client, api_url: []const u8) void {
    _ = io;
    const cookie_len = Store.session_cookie_len;
    if (cookie_len == 0) return;
    var old_cookie: [256]u8 = undefined;
    @memcpy(old_cookie[0..cookie_len], Store.session_cookie[0..cookie_len]);
    Engine.performLogout(client, api_url, old_cookie[0..cookie_len]) catch {};
    crypto.secureZero(u8, &Store.session_cookie);
    Store.session_cookie_len = 0;
}

fn getLogTimezone(client: *Client, endpoint: []const u8) !struct { offset: i64, suffix: []const u8 } {
    var buf: [16384]u8 = undefined;
    const body = try Engine.fetchApiToBuffer(client, endpoint, "", &buf);
    var scanner = Scanner.initCompleteInput(Store.allocator, body);
    defer scanner.deinit();
    if ((try scanner.next()) != .object_begin) return error.InvalidJson;
    var time_str: ?[]const u8 = null;
    while (true) {
        const token = try scanner.next();
        if (token == .object_end) break;
        if (mem.eql(u8, token.string, "data")) {
            if ((try scanner.next()) != .array_begin) break;
            if ((try scanner.peekNextTokenType()) == .object_begin) {
                _ = try scanner.next();
                while (true) {
                    const field_t = try scanner.next();
                    if (field_t == .object_end) break;
                    if (mem.eql(u8, field_t.string, "time")) {
                        time_str = (try scanner.next()).string;
                    } else {
                        try scanner.skipValue();
                    }
                }
            }
            break;
        } else {
            try scanner.skipValue();
        }
    }
    const final_time = time_str orelse return error.NoTime;
    if (mem.endsWith(u8, final_time, "Z")) return .{ .offset = 0, .suffix = "Z" };
    const idx = mem.lastIndexOfAny(u8, final_time, "+-") orelse return .{ .offset = 0, .suffix = "Z" };
    const raw_suffix = final_time[idx..];
    if (raw_suffix.len < 6) return .{ .offset = 0, .suffix = "Z" };
    const hours = try fmt.parseInt(i64, raw_suffix[1..3], 10);
    const mins = try fmt.parseInt(i64, raw_suffix[4..6], 10);
    const total = hours * 3600 + mins * 60;
    return .{
        .offset = if (raw_suffix[0] == '+') total else -total,
        .suffix = raw_suffix,
    };
}

fn getActualUserSessionStart(io: Io) i64 {
    const real_now = Clock.real.now(io).toSeconds();
    const boot_now = Clock.boot.now(io).toSeconds();
    return real_now - boot_now;
}
