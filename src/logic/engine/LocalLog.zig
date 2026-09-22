const std = @import("std");
const c_std = std.c;
const posix = std.posix;
const system = posix.system;
const Io = std.Io;
const mem = std.mem;
const hash = std.hash;
const Dir = Io.Dir;
const File = Io.File;
const Terminal = Io.Terminal;
const Mode = Io.Terminal.Mode;
const Allocator = mem.Allocator;

const Store = @import("../../data/Store.zig");
const Format = @import("../../view/Format.zig");
const LogLine = @import("../../view/LogLine.zig");
const Json = @import("../parser/Json.zig");

pub fn streamFromFile(io: Io, _: Allocator, log_path: []const u8, start_ts: []const u8, w: File, term_w: u16, scan_limit_mb: usize, no_color: bool) !usize {
    const agh_uid = blk: {
        const pw = c_std.getpwnam("adguardhome");
        break :blk if (pw) |ptr| ptr.uid else 0;
    };
    const is_root = system.getuid() == 0;
    var switched_to_agh = false;
    if (is_root and agh_uid != 0) {
        if (system.setresuid(agh_uid, agh_uid, 0) == 0) switched_to_agh = true;
    }
    const file = Dir.cwd().openFile(io, log_path, .{ .mode = .read_only }) catch |err| blk: {
        if (switched_to_agh and err == error.AccessDenied) {
            _ = system.setresuid(0, 0, 0);
            switched_to_agh = false;
            break :blk try Dir.cwd().openFile(io, log_path, .{ .mode = .read_only });
        }
        return err;
    };
    defer file.close(io);
    defer if (switched_to_agh) {
        _ = system.setresuid(0, 0, 0);
    };
    const stat_data = try file.stat(io);
    const size = @as(usize, @intCast(stat_data.size));
    if (size == 0) return 0;
    var mmap_obj = try file.createMemoryMap(io, .{
        .len = size,
        .protection = .{ .read = true, .write = false },
    });
    defer mmap_obj.destroy(io);
    const log_slice = mmap_obj.memory;
    var pos: usize = size;
    const limit_bytes = scan_limit_mb * 1024 * 1024;
    const limit: usize = if (size > limit_bytes) size - limit_bytes else 0;
    var start_offset: usize = 0;
    const raw_ptr = log_slice.ptr;
    while (pos > limit) {
        pos -= 1;
        if (raw_ptr[pos] == '\n' or pos == 0) {
            const line_start = if (pos == 0) @as(usize, 0) else pos + 1;
            const line = log_slice[line_start..size];
            if (Json.getJsonValueRaw(line, "T")) |item_ts| {
                if (item_ts.len >= 19) {
                    if (mem.order(u8, item_ts[0..19], start_ts[0..19]) == .lt) {
                        start_offset = line_start;
                        break;
                    }
                }
            }
        }
    }
    Store.scratch_fba.end_index = size - start_offset;
    const is_boundary_eligible = if (Store.session_start_anchor_len >= 19 and start_ts.len >= 19)
        mem.order(u8, start_ts[0..19], Store.session_start_anchor[0..19]) == .lt
    else
        false;
    const terminal_mode = try Mode.detect(io, w, no_color, false);
    var terminal_wrap_buf: [1024]u8 = undefined;
    var terminal_writer_wrapper = w.writer(io, &terminal_wrap_buf);
    var terminal = Terminal{ .writer = &terminal_writer_wrapper.interface, .mode = terminal_mode };
    var parsed_count: usize = 0;
    var base_reader = Io.Reader.fixed(log_slice[start_offset..size]);
    var hasher = hash.Wyhash.init(0);
    var h_buf: [4096]u8 = undefined;
    var h_reader_obj = base_reader.hashed(&hasher, &h_buf);
    const reader = &h_reader_obj.reader;
    while (true) {
        const line = reader.takeDelimiter('\n') catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.StreamTooLong => return error.SystemResources,
        } orelse break;
        if (line.len < 50) continue;
        const item_ts = Json.getJsonValueRaw(line, "T") orelse "";
        if (item_ts.len < 19) continue;
        if (Store.custom_end_ts_len > 0) {
            if (mem.order(u8, item_ts, Store.custom_end_ts[0..Store.custom_end_ts_len]) == .gt) {
                Store.should_exit = true;
                break;
            }
        }
        if (is_boundary_eligible and !Store.has_drawn_boundary) {
            if (mem.order(u8, item_ts, Store.session_start_anchor[0..Store.session_start_anchor_len]) != .lt) {
                Store.io_mutex.lockUncancelable(io);
                var b_buf: [1024]u8 = undefined;
                const b_len = @min(term_w, b_buf.len - 1);
                @memset(b_buf[0..b_len], '-');
                b_buf[b_len] = '\n';
                try w.writeStreamingAll(io, b_buf[0 .. b_len + 1]);
                Store.io_mutex.unlock(io);
                Store.has_drawn_boundary = true;
            }
        }
        if (mem.order(u8, item_ts, start_ts) == .gt) {
            if (!Format.isExcessiveFuture(io, item_ts)) {
                try LogLine.displayLogItemRaw(&terminal, io, Store.net_client_fba.allocator(), line, term_w, w, false, no_color);
                const safe_len = @min(item_ts.len, Store.last_seen_ts.len);
                @memcpy(Store.last_seen_ts[0..safe_len], item_ts[0..safe_len]);
                Store.last_seen_ts_len = safe_len;
                parsed_count += 1;
            }
        }
    }
    Store.state_lock.lockUncancelable(io);
    Store.log_content_hash = hasher.final();
    Store.state_lock.unlock(io);
    return parsed_count;
}
