const std = @import("std");
const mem = std.mem;
const base64 = std.base64;
const Io = std.Io;
const net = Io.net;
const HostName = Io.net.HostName;
const Ip4Address = Io.net.Ip4Address;
const Ip6Address = Io.net.Ip6Address;
const Decoder = base64.standard.Decoder;

const Format = @import("../../view/Format.zig");

fn parseSvcb(packet: []const u8, data_off: usize, data_len: u16, writer: anytype) !void {
    if (data_len < 2) return;
    const priority = mem.readInt(u16, packet[data_off .. data_off + 2][0..2], .big);
    var u_buf: [20]u8 = undefined;
    try writer.writeAll(u_buf[0..Format.writeUint(&u_buf, priority)]);
    try writer.writeByte(' ');
    var pos: usize = data_off + 2;
    const end_limit = data_off + data_len;
    if (pos < end_limit) {
        if (packet[pos] == 0) {
            try writer.writeAll(". ");
            pos += 1;
        } else {
            var name_buf: [HostName.max_len]u8 = undefined;
            const expanded = try HostName.expand(packet, pos, &name_buf);
            try writer.writeAll(expanded[1].bytes);
            try writer.writeAll(". ");
            pos += expanded[0];
        }
    }
    while (pos + 4 <= end_limit) {
        const key = mem.readInt(u16, packet[pos .. pos + 2][0..2], .big);
        const val_len = mem.readInt(u16, packet[pos + 2 .. pos + 4][0..2], .big);
        pos += 4;
        const next_param = pos + val_len;
        if (next_param > end_limit) break;
        const val = packet[pos..next_param];
        switch (key) {
            1 => {
                try writer.writeAll("alpn=\"");
                var v_pos: usize = 0;
                while (v_pos < val.len) {
                    const l = val[v_pos];
                    v_pos += 1;
                    if (v_pos > 1) try writer.writeByte(',');
                    const v_end = @min(v_pos + l, val.len);
                    try writer.writeAll(val[v_pos..v_end]);
                    v_pos = v_end;
                }
                try writer.writeByte('\"');
            },
            3 => {
                if (val.len == 2) {
                    const port = mem.readInt(u16, val[0..2][0..2], .big);
                    try writer.writeAll("port=");
                    try writer.writeAll(u_buf[0..Format.writeUint(&u_buf, port)]);
                }
            },
            4 => {
                try writer.writeAll("ipv4hint=");
                var v_pos: usize = 0;
                while (v_pos + 4 <= val.len) {
                    if (v_pos > 0) try writer.writeByte(',');
                    const addr = Ip4Address{ .bytes = val[v_pos..][0..4].*, .port = 0 };
                    try writer.print("{d}.{d}.{d}.{d}", .{ addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3] });
                    v_pos += 4;
                }
            },
            6 => {
                try writer.writeAll("ipv6hint=");
                var v_pos: usize = 0;
                while (v_pos + 16 <= val.len) {
                    if (v_pos > 0) try writer.writeByte(',');
                    const addr = Ip6Address{ .bytes = val[v_pos..][0..16].*, .port = 0 };
                    const unresolved = Ip6Address.Unresolved{ .bytes = addr.bytes, .interface_name = null };
                    try unresolved.format(writer);
                    v_pos += 16;
                }
            },
            else => {
                try writer.writeAll("key");
                try writer.writeAll(u_buf[0..Format.writeUint(&u_buf, key)]);
                try writer.writeAll("=len");
                try writer.writeAll(u_buf[0..Format.writeUint(&u_buf, val_len)]);
            },
        }
        pos = next_param;
        if (pos < end_limit) try writer.writeByte(' ');
    }
}

pub fn decodeAndParseDnsAnswer(b64_str: []const u8, writer: anytype) !void {
    if (b64_str.len == 0) return;
    const decoder = Decoder;
    var scratch: [2048]u8 align(1) = undefined;
    const calc_size = decoder.calcSizeForSlice(b64_str) catch return error.InvalidBase64;
    if (calc_size > scratch.len) return error.DnsResponseTooLarge;
    try decoder.decode(&scratch, b64_str);
    const packet = scratch[0..calc_size];
    if (packet.len < 12) return;
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
    var found_count: usize = 0;
    var u_buf: [20]u8 = undefined;
    var a: usize = 0;
    while (a < ans_count and pos + 10 <= packet.len) : (a += 1) {
        if (found_count > 0) try writer.writeAll(" | ");
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
        pos = data_off + data_len;
        if (pos > packet.len) break;
        const rdata = packet[data_off..pos];
        switch (rr_type) {
            1 => {
                if (data_len == 4) {
                    const addr = Ip4Address{ .bytes = rdata[0..4].*, .port = 0 };
                    try writer.print("{d}.{d}.{d}.{d}", .{ addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3] });
                    found_count += 1;
                }
            },
            28 => {
                if (data_len == 16) {
                    const addr = Ip6Address{ .bytes = rdata[0..16].*, .port = 0 };
                    const unresolved = Ip6Address.Unresolved{ .bytes = addr.bytes, .interface_name = null };
                    try unresolved.format(writer);
                    found_count += 1;
                }
            },
            2, 5, 12 => {
                var name_out_buf: [HostName.max_len]u8 = undefined;
                const expanded = try HostName.expand(packet, data_off, &name_out_buf);
                try writer.writeAll(expanded[1].bytes);
                try writer.writeByte('.');
                found_count += 1;
            },
            64, 65 => {
                try parseSvcb(packet, data_off, data_len, writer);
                found_count += 1;
            },
            else => {
                try writer.writeAll("TYPE");
                try writer.writeAll(u_buf[0..Format.writeUint(&u_buf, rr_type)]);
                found_count += 1;
            },
        }
    }
}
