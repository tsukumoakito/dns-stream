const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const heap = std.heap;
const ascii = std.ascii;
const process = std.process;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Terminal = Io.Terminal;
const Iterator = process.Args.Iterator;
const Allocator = mem.Allocator;
const FixedBufferAllocator = heap.FixedBufferAllocator;
const StaticStringMap = std.StaticStringMap;

const Collector = @import("terminal/Collector.zig");

pub const is_enabled = true;

const clr_title = "\x1b[1;4;37m";
const clr_val = "\x1b[1;33m";
const clr_perc = "\x1b[1;32m";
const clr_reset = "\x1b[0m";

var cached_system_ram: u64 = 0;

pub const DiagnosticContext = struct {
    enabled: bool = false,
    ansi_visible: bool = false,
    mem_enabled: bool = false,
    debug_only: bool = false,
    proc_status_file: ?File = null,

    pub fn fromSystemArgs(it: *Iterator) DiagnosticContext {
        var self = DiagnosticContext{};
        const DebugFlag = enum { debug, only, ansi, mem };
        const flag_map = StaticStringMap(DebugFlag).initComptime(.{
            .{ "--debug", .debug },
            .{ "--debug-only", .only },
            .{ "--debug-ansi", .ansi },
            .{ "--debug-mem", .mem },
        });

        _ = it.next();

        while (it.next()) |arg| {
            const flag = flag_map.get(arg) orelse continue;
            switch (flag) {
                .debug => self.enabled = true,
                .only => {
                    self.debug_only = true;
                    self.enabled = true;
                },
                .ansi => self.ansi_visible = true,
                .mem => self.mem_enabled = true,
            }
        }
        return self;
    }

    pub fn deinit(self: *DiagnosticContext, io: Io) void {
        if (self.proc_status_file) |f| {
            f.close(io);
            self.proc_status_file = null;
        }
    }

    pub fn formatSizeBuf(buf: []u8, bytes: usize) []const u8 {
        var f = Writer.fixed(buf);
        const bytes_f = @as(f32, @floatFromInt(bytes));
        if (bytes >= 1073741824) {
            f.print("{d:.2} GB", .{bytes_f / 1073741824.0}) catch {};
        } else if (bytes >= 1048576) {
            f.print("{d:.2} MB", .{bytes_f / 1048576.0}) catch {};
        } else if (bytes >= 1024) {
            f.print("{d:.1} KB", .{bytes_f / 1024.0}) catch {};
        } else {
            f.print("{d} B", .{bytes}) catch {};
        }
        return f.buffered();
    }

    pub fn appendStatRow(self: DiagnosticContext, terminal: *Terminal, collector: *Collector, label: []const u8, val: usize, max: u64, val_suffix: []const u8) !void {
        _ = self;
        _ = terminal;
        const old_vis = collector.ansi_visible;
        collector.ansi_visible = false;
        defer collector.ansi_visible = old_vis;
        var w = collector.writer();
        try w.print("  {s:<20}: ", .{label});
        var s_buf: [32]u8 = undefined;
        const v_str = if (val_suffix.len > 0) blk: {
            var f = Writer.fixed(&s_buf);
            f.print("{d}{s}", .{ val, val_suffix }) catch {};
            break :blk f.buffered();
        } else formatSizeBuf(&s_buf, val);
        try w.print("{s}{s:>12}{s} / ", .{ clr_val, v_str, clr_reset });
        var m_buf: [32]u8 = undefined;
        const m_str = if (val_suffix.len > 0) blk: {
            var f = Writer.fixed(&m_buf);
            f.print("{d}{s}", .{ max, val_suffix }) catch {};
            break :blk f.buffered();
        } else formatSizeBuf(&m_buf, @intCast(max));
        const perc = if (max > 0) (@as(f32, @floatFromInt(val)) / @as(f32, @floatFromInt(max))) * 100.0 else 0.0;
        try w.print("{s:<15} ({s}{d:>5.1}%{s})\n", .{ m_str, clr_perc, perc, clr_reset });
    }

    fn getSystemTotalRam() u64 {
        if (cached_system_ram > 0) return cached_system_ram;
        cached_system_ram = process.totalSystemMemory() catch 0;
        return cached_system_ram;
    }

    pub fn appendMemoryStats(self: *DiagnosticContext, collector: *Collector, fba: *FixedBufferAllocator, provider: anytype, io: Io) !void {
        if (!self.mem_enabled) return;
        const old_vis = collector.ansi_visible;
        collector.ansi_visible = false;
        defer collector.ansi_visible = old_vis;
        var w = collector.writer();
        if (collector.lines.items.len > 0 and collector.lines.items[collector.lines.items.len - 1].text.len > 0) {
            try w.writeAll("\n");
        }
        try w.writeAll(clr_title ++ "--- Memory Usage Statistics ---" ++ clr_reset ++ "\n");
        if (self.proc_status_file == null) {
            self.proc_status_file = Dir.cwd().openFile(io, "/proc/self/status", .{ .mode = .read_only }) catch null;
        }
        if (self.proc_status_file) |f| {
            var buf: [4096]u8 = undefined;
            const n = f.readPositional(io, &.{&buf}, 0) catch 0;
            if (n > 0) {
                if (mem.indexOf(u8, buf[0..n], "VmRSS:")) |idx| {
                    var i = idx + 6;
                    while (i < n and ascii.isWhitespace(buf[i])) : (i += 1) {}
                    const start = i;
                    while (i < n and ascii.isDigit(buf[i])) : (i += 1) {}
                    const rss = (fmt.parseInt(usize, buf[start..i], 10) catch 0) * 1024;
                    try self.appendStatRow(collector.terminal, collector, "System Process RSS", rss, getSystemTotalRam(), "");
                }
            }
        }
        try self.appendStatRow(collector.terminal, collector, "Render Buffer (FBA)", fba.end_index, @as(u64, fba.buffer.len), "");
        if (comptime @hasDecl(provider, "appendDiagnosticStats")) {
            try provider.appendDiagnosticStats(collector, self.*);
        }
    }

    pub fn appendSection(self: DiagnosticContext, collector: *Collector, is_first: *bool, config: anytype, io: Io, allocator: Allocator) !void {
        _ = allocator;
        if (!self.enabled) return;
        const original_vis = collector.ansi_visible;
        collector.ansi_visible = false;
        var w = collector.writer();
        if (!is_first.*) try w.writeAll("\n");
        try w.writeAll(clr_title ++ config.title ++ clr_reset ++ "\n");
        is_first.* = false;
        var child = try process.spawn(io, .{
            .argv = config.argv,
            .stdout_behavior = .pipe,
            .stderr_behavior = .pipe,
            .stdin_behavior = .ignore,
        });
        collector.ansi_visible = self.ansi_visible;
        defer collector.ansi_visible = original_vis;
        var read_buf: [1024]u8 = undefined;
        while (true) {
            const n = try child.stdout.readStreaming(io, &.{&read_buf});
            if (n == 0) break;
            try w.writeAll(read_buf[0..n]);
        }
        _ = try child.wait(io);
    }
};
