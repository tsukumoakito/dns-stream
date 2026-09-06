const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const heap = std.heap;
const http = std.http;
const File = Io.File;
const Clock = Io.Clock;
const Writer = Io.Writer;
const Duration = Io.Duration;
const Terminal = Io.Terminal;
const Operation = Io.Operation;
const Batch = Io.Batch;
const Client = http.Client;
const Allocator = mem.Allocator;
const FixedBufferAllocator = heap.FixedBufferAllocator;

const Store = @import("../../../data/Store.zig");
const Engine = @import("../../../logic/Engine.zig");
const Format = @import("../../../view/Format.zig");
const Collector = @import("../Collector.zig");

pub fn heartbeatTask(io: Io, api_url: []const u8, stop_flag: *bool, base_allocator: Allocator) void {
    var hb_client = Client{
        .allocator = base_allocator,
        .io = io,
        .ca_bundle = .empty,
        .now = Clock.real.now(io),
    };
    defer hb_client.deinit();
    hb_client.ca_bundle.rescan(base_allocator, io, Clock.real.now(io)) catch return;
    var buf: [128]u8 = undefined;
    var url_buf: [512]u8 = undefined;
    const status_endpoint = fmt.bufPrint(&url_buf, "{s}/status", .{api_url}) catch return;
    while (!Store.should_exit and !stop_flag.*) {
        _ = Engine.fetchApiToBuffer(&hb_client, status_endpoint, "", &buf) catch {};
        var i: usize = 0;
        while (i < 50 and !stop_flag.*) : (i += 1) {
            io.sleep(Duration.fromMilliseconds(100), .awake) catch {};
        }
    }
}

pub fn diagnosticTask(io: Io, diag_ctx: anytype, diag_rows: u16, terminal_mode: Terminal.Mode) void {
    const stdout_file = File.stdout();
    var mutable_ctx = diag_ctx;
    var thread_work_buf: [8192]u8 = undefined;
    var thread_fba = FixedBufferAllocator.init(&thread_work_buf);
    var terminal_wrap_buf: [1024]u8 = undefined;
    var terminal_writer_wrapper = stdout_file.writer(io, &terminal_wrap_buf);
    var terminal = Terminal{ .writer = &terminal_writer_wrapper.interface, .mode = terminal_mode };
    var frame_buf: [16384]u8 = undefined;
    var storage: [1]Operation.Storage = undefined;
    while (!Store.should_exit) {
        io.sleep(Duration.fromSeconds(1), .awake) catch {};
        if (!Store.is_footer_fixed) continue;
        const winsize = getTermSize();
        Store.state_lock.lockSharedUncancelable(io);
        thread_fba.reset();
        var collector_obj = Collector.init(thread_fba.allocator(), &terminal);
        defer collector_obj.deinit();
        collector_obj.ansi_visible = mutable_ctx.ansi_visible;
        mutable_ctx.appendMemoryStats(&collector_obj, &Store.scratch_fba, Store, io) catch {
            Store.state_lock.unlockShared(io);
            continue;
        };
        var f_writer = Writer.fixed(&frame_buf);
        f_writer.writeAll("\x1b[?25l\x1b7") catch {};
        const start_row = if (winsize.row > diag_rows) winsize.row - diag_rows else 1;
        f_writer.print("\x1b[{d};1H\x1b[K{s}", .{ start_row - 1, Format.clr_dim }) catch {};
        f_writer.splatByteAll('-', winsize.col) catch {};
        f_writer.print("{s}\n", .{Format.clr_reset}) catch {};
        for (collector_obj.lines.items, 0..) |line, i| {
            if (i >= diag_rows) break;
            f_writer.print("\x1b[{d};1H\x1b[K{s}", .{ start_row + i, line.text }) catch {};
        }
        f_writer.writeAll("\x1b8\x1b[?25h") catch {};
        const frame_data = f_writer.buffered();
        Store.state_lock.unlockShared(io);
        Store.io_mutex.lockUncancelable(io);
        var batch = Batch.init(&storage);
        _ = batch.add(.{ .file_write_streaming = .{ .file = stdout_file, .data = &.{frame_data} } });
        batch.awaitConcurrent(io, .none) catch {};
        Store.io_mutex.unlock(io);
    }
}

fn getTermSize() struct { row: u16, col: u16 } {
    var ws = posix.winsize{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const rc = linux.ioctl(posix.STDOUT_FILENO, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (linux.errno(rc) != .SUCCESS or ws.row == 0) {
        return .{ .row = 24, .col = 80 };
    }
    return .{ .row = ws.row, .col = ws.col };
}
