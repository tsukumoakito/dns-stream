const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const debug = std.debug;
const process = std.process;
const builtin = std.builtin;
const File = Io.File;
const Threaded = Io.Threaded;
const Iterator = process.Args.Iterator;
const Allocator = mem.Allocator;

pub var use_custom_panic: bool = true;

pub fn getDiagContext() type {
    const root = @import("root");

    if (@hasDecl(root, "Diagnostic")) {
        const M = @field(root, "Diagnostic");
        if (@hasDecl(M, "DiagnosticContext")) return M.DiagnosticContext;
    }

    return struct {
        enabled: bool = false,
        mem_enabled: bool = false,
        ansi_visible: bool = false,
        debug_only: bool = false,

        pub fn fromSystemArgs(it: *Iterator) @This() {
            _ = it;
            return .{};
        }
        pub fn deinit(self: *@This(), io: Io) void {
            _ = self;
            _ = io;
        }
        pub const formatSizeBuf: ?*const fn (buf: []u8, bytes: usize) []const u8 = null;
        pub fn appendMemoryStats(self: @This(), collector: anytype, fba: anytype, provider: anytype, io: Io) !void {
            _ = self;
            _ = collector;
            _ = fba;
            _ = provider;
            _ = io;
        }
        pub fn appendSection(self: @This(), collector: anytype, is_first: anytype, config: anytype, io: Io, allocator: Allocator) !void {
            _ = self;
            _ = collector;
            _ = is_first;
            _ = config;
            _ = io;
            _ = allocator;
        }
    };
}

pub fn handlePanic(
    msg: []const u8,
    stack_trace: ?*builtin.StackTrace,
    ret_addr: ?usize,
    comptime StoreModule: type,
) noreturn {
    _ = ret_addr;
    if (!use_custom_panic) {
        rawWrite("PANIC: ");
        rawWrite(msg);
        rawWrite("\n");
    } else {
        rawWrite("\n\x1b[1;41;97m !!! PANIC !!! \x1b[0m\n");
        rawWrite("MESSAGE: ");
        rawWrite(msg);
        rawWrite("\n\n--- BLACKBOX STATE (Dynamic Recovery) ---\n");

        const info = @typeInfo(StoreModule);
        inline for (info.@"struct".decls) |decl| {
            const T = @TypeOf(@field(StoreModule, decl.name));

            if (T == []u8 or T == []const u8) {
                const val = @field(StoreModule, decl.name);
                rawWrite("  ");
                rawWrite(decl.name);
                rawWrite(": ");
                if (val.len > 512) {
                    rawWrite(val[0..512]);
                    rawWrite("... (truncated)");
                } else {
                    rawWrite(val);
                }
                rawWrite("\n");
            } else if (T == usize or T == u64 or T == i64 or T == u32) {
                const val = @field(StoreModule, decl.name);
                rawWrite("  ");
                rawWrite(decl.name);
                rawWrite(": ");
                printInt(@intCast(val));
                rawWrite("\n");
            }
        }
        rawWrite("------------------------------------------\n");
    }

    if (stack_trace) |st| {
        rawWrite("\nSTACK TRACE:\n");
        const debug_st = debug.StackTrace{
            .return_addresses = st.instruction_addresses[0..st.index],
            .skipped = .none,
        };
        debug.dumpStackTrace(&debug_st);
    }

    rawWrite("\x1b[?25h\n");

    process.exit(1);
}

fn rawWrite(data: []const u8) void {
    const stderr = File.stderr();
    stderr.writeStreamingAll(Threaded.global_single_threaded.io(), data) catch {};
}

fn printInt(val: u64) void {
    if (val == 0) {
        rawWrite("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var v = val;
    while (v > 0) {
        i -= 1;
        buf[i] = @intCast((v % 10) + '0');
        v /= 10;
    }
    rawWrite(buf[i..]);
}
