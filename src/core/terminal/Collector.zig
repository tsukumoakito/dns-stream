const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const unicode = std.unicode;
const Writer = Io.Writer;
const Terminal = Io.Terminal;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

const Self = @This();

pub const LineInfo = struct {
    text: []const u8,
    visual_width: usize,
};

allocator: Allocator,
terminal: *Terminal,
lines: ArrayList(LineInfo) = .empty,
current_line: ArrayList(u8) = .empty,
visual_width: usize = 0,
in_ansi: bool = false,
ansi_visible: bool = false,
base_writer: Writer,

const vtable = Writer.VTable{
    .drain = drainInternal,
};

pub fn init(allocator: Allocator, terminal: *Terminal) Self {
    return .{
        .allocator = allocator,
        .terminal = terminal,
        .base_writer = .{
            .vtable = &vtable,
            .buffer = &.{},
            .end = 0,
        },
    };
}

pub fn writer(self: *Self) *Writer {
    return &self.base_writer;
}

fn drainInternal(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const self: *Self = @fieldParentPtr("base_writer", w);

    for (data[0 .. data.len - 1]) |slice| {
        self.processBytes(slice) catch return error.WriteFailed;
    }

    const last = data[data.len - 1];
    var i: usize = 0;
    while (i < splat) : (i += 1) {
        self.processBytes(last) catch return error.WriteFailed;
    }

    return Writer.countSplat(data, splat);
}

fn processBytes(self: *Self, bytes: []const u8) !void {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const b = bytes[i];

        if (b == '\n') {
            try self.flushLine();
            continue;
        }

        if (b == '\x1b') {
            self.in_ansi = true;
            if (self.ansi_visible) {
                try self.current_line.appendSlice(self.allocator, "^[");
                self.visual_width += 2;
            } else {
                try self.current_line.append(self.allocator, b);
            }
            continue;
        }

        if (self.in_ansi) {
            try self.current_line.append(self.allocator, b);
            if (self.ansi_visible) self.visual_width += 1;
            if ((b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z')) {
                self.in_ansi = false;
            }
            continue;
        }

        if (b == '\t') {
            const tab_size = 8;
            const space_count = tab_size - (self.visual_width % tab_size);
            try self.current_line.appendNTimes(self.allocator, ' ', space_count);
            self.visual_width += space_count;
        } else {
            try self.current_line.append(self.allocator, b);
            if ((b & 0xC0) != 0x80) self.visual_width += 1;
        }
    }
}

pub fn flushLine(self: *Self) !void {
    if (self.current_line.items.len == 0 and self.visual_width == 0) {
        try self.lines.append(self.allocator, .{ .text = "", .visual_width = 0 });
        return;
    }

    const text = try self.current_line.toOwnedSlice(self.allocator);
    try self.lines.append(self.allocator, .{ .text = text, .visual_width = self.visual_width });

    self.visual_width = 0;
    self.in_ansi = false;
}

pub fn deinit(self: *Self) void {
    self.lines.deinit(self.allocator);
    self.current_line.deinit(self.allocator);
}

pub fn getVisualWidth(text: []const u8, terminal: *Terminal, ansi_visible: bool) usize {
    _ = terminal;
    var width: usize = 0;
    var in_ansi = false;
    var i: usize = 0;
    while (i < text.len) {
        const b = text[i];
        if (b == '\x1b') {
            if (ansi_visible) width += 2;
            in_ansi = true;
            i += 1;
            continue;
        }
        if (in_ansi) {
            if (ansi_visible) width += 1;
            if ((b >= 'A' and b <= 'Z') or (b >= 'a' and b <= 'z')) in_ansi = false;
            i += 1;
            continue;
        }
        if (b == 0) {
            i += 1;
            continue;
        }
        if (b == '\t') {
            const tab_size = 8;
            width += tab_size - (width % tab_size);
            i += 1;
        } else if ((b & 0x80) == 0) {
            width += 1;
            i += 1;
        } else {
            const len = unicode.utf8ByteSequenceLength(b) catch 1;
            width += 1;
            i += len;
        }
    }
    return width;
}
