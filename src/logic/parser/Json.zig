const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const json = std.json;
const Scanner = json.Scanner;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

const Store = @import("../../data/Store.zig");

pub const EntryKey = enum {
    time,
    client,
    domain,
    answer,
    upstream,
    cached,
};

pub fn getJsonValueRaw(input_json: []const u8, key: []const u8) ?[]const u8 {
    var scanner = Scanner.initCompleteInput(Store.allocator, input_json);
    defer scanner.deinit();
    if ((scanner.next() catch return null) != .object_begin) return null;
    while (true) {
        const token = scanner.next() catch break;
        if (token == .object_end) break;
        const is_match = mem.eql(u8, token.string, key);
        _ = scanner.peekNextTokenType() catch break;
        const val_start = scanner.cursor;
        const val_type = scanner.peekNextTokenType() catch break;
        scanner.skipValue() catch break;
        if (is_match) {
            var slice = input_json[val_start..scanner.cursor];
            if (val_type == .string) {
                if (slice.len >= 2) slice = slice[1 .. slice.len - 1];
            }
            return slice;
        }
    }
    return null;
}

pub fn getCompatibleValue(input_json: []const u8, key: EntryKey) ?[]const u8 {
    return switch (key) {
        .time => getJsonValueRaw(input_json, "time") orelse getJsonValueRaw(input_json, "T"),
        .client => getJsonValueRaw(input_json, "client") orelse getJsonValueRaw(input_json, "IP"),
        .domain => blk: {
            if (getJsonValueRaw(input_json, "question")) |q| {
                if (getJsonValueRaw(q, "name")) |n| break :blk n;
            }
            break :blk getJsonValueRaw(input_json, "QH");
        },
        .answer => getJsonValueRaw(input_json, "answer") orelse getJsonValueRaw(input_json, "Answer"),
        .upstream => getJsonValueRaw(input_json, "upstream") orelse getJsonValueRaw(input_json, "Upstream"),
        .cached => getJsonValueRaw(input_json, "cached") orelse getJsonValueRaw(input_json, "Cached"),
    };
}

pub fn writeJsonUnescaped(w: anytype, raw: []const u8) !void {
    var start: usize = 0;
    while (mem.indexOfScalarPos(u8, raw, start, '\\')) |esc_pos| {
        if (esc_pos > start) try w.writeAll(raw[start..esc_pos]);
        if (esc_pos + 1 >= raw.len) {
            start = raw.len;
            break;
        }
        const c = raw[esc_pos + 1];
        switch (c) {
            '\"' => try w.writeByte('\"'),
            '\\' => try w.writeByte('\\'),
            '/' => try w.writeByte('/'),
            'b' => try w.writeByte(0x08),
            'f' => try w.writeByte(0x0C),
            'n' => try w.writeByte('\n'),
            'r' => try w.writeByte('\r'),
            't' => try w.writeByte('\t'),
            else => {
                try w.writeByte('\\');
                try w.writeByte(c);
            },
        }
        start = esc_pos + 2;
    }
    if (start < raw.len) try w.writeAll(raw[start..]);
}

pub fn getNewestTimestampInChunk(raw_json: []const u8) ?[]const u8 {
    var scanner = Scanner.initCompleteInput(Store.allocator, raw_json);
    defer scanner.deinit();
    if ((scanner.next() catch return null) != .object_begin) return null;
    while (true) {
        const token = scanner.next() catch break;
        if (token == .object_end) break;
        if (mem.eql(u8, token.string, "data")) {
            if ((scanner.next() catch break) != .array_begin) break;
            const start = scanner.cursor;
            if ((scanner.peekNextTokenType() catch .array_end) == .array_end) return null;
            scanner.skipValue() catch break;
            return getCompatibleValue(raw_json[start..scanner.cursor], .time);
        } else {
            scanner.skipValue() catch break;
        }
    }
    return getCompatibleValue(raw_json, .time);
}

pub fn getOldestTimestampInChunk(raw_json: []const u8) ?[]const u8 {
    var scanner = Scanner.initCompleteInput(Store.allocator, raw_json);
    defer scanner.deinit();
    if ((scanner.next() catch return null) != .object_begin) return null;
    var last_item: ?[]const u8 = null;
    while (true) {
        const token = scanner.next() catch break;
        if (token == .object_end) break;
        if (mem.eql(u8, token.string, "data")) {
            if ((scanner.next() catch break) != .array_begin) break;
            while ((scanner.peekNextTokenType() catch .array_end) != .array_end) {
                const start = scanner.cursor;
                scanner.skipValue() catch break;
                last_item = raw_json[start..scanner.cursor];
            }
            if (last_item) |item| return getCompatibleValue(item, .time);
            return null;
        } else {
            scanner.skipValue() catch break;
        }
    }
    return getCompatibleValue(raw_json, .time);
}

pub fn processJsonBulkReverse(raw_json: []const u8, callback: *const fn (Allocator, []const u8) anyerror!void) !void {
    var scanner = Scanner.initCompleteInput(Store.allocator, raw_json);
    defer scanner.deinit();
    const la = Store.net_client_fba.allocator();
    var list: ArrayList([]const u8) = .empty;
    defer list.deinit(la);
    if ((scanner.next() catch return) != .object_begin) {
        try callback(la, raw_json);
        return;
    }
    var has_data = false;
    while (true) {
        const token = scanner.next() catch break;
        if (token == .object_end) break;
        if (mem.eql(u8, token.string, "data")) {
            if ((scanner.next() catch break) != .array_begin) break;
            has_data = true;
            while ((scanner.peekNextTokenType() catch .array_end) != .array_end) {
                const start = scanner.cursor;
                try scanner.skipValue();
                try list.append(la, raw_json[start..scanner.cursor]);
            }
            break;
        } else {
            try scanner.skipValue();
        }
    }
    if (!has_data) {
        try callback(la, raw_json);
        return;
    }
    var i: usize = list.items.len;
    while (i > 0) {
        i -= 1;
        try callback(la, list.items[i]);
    }
}
