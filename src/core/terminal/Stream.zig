const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const system = posix.system;
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const http = std.http;
const heap = std.heap;
const debug = std.debug;
const crypto = std.crypto;
const process = std.process;
const Client = http.Client;
const Dir = Io.Dir;
const File = Io.File;
const Clock = Io.Clock;
const Group = Io.Group;
const Writer = Io.Writer;
const Terminal = Io.Terminal;
const Operation = Io.Operation;
const Batch = Io.Batch;
const Mode = Io.Terminal.Mode;
const Environ = process.Environ;
const Allocator = mem.Allocator;
const FixedBufferAllocator = heap.FixedBufferAllocator;

const Store = @import("../../data/Store.zig");
const Auth = @import("../../logic/Auth.zig");
const Config = @import("../../logic/Config.zig");
const Engine = @import("../../logic/Engine.zig");
const Json = @import("../../logic/parser/Json.zig");
const constants = @import("../../root.zig");
const Format = @import("../../view/Format.zig");
const LogLine = @import("../../view/LogLine.zig");
const Crypt = @import("../vault/Crypt.zig");
const AnchorLogic = @import("AnchorLogic.zig");
const Collector = @import("Collector.zig");
const Background = @import("tasks/Background.zig");

pub fn getTermSize() struct { row: u16, col: u16 } {
    var ws = posix.winsize{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const rc = linux.ioctl(posix.STDOUT_FILENO, linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (linux.errno(rc) != .SUCCESS or ws.row == 0) {
        return .{ .row = 24, .col = 80 };
    }
    return .{ .row = ws.row, .col = ws.col };
}

pub fn getCursorRow(io: Io) !u16 {
    const stdout = File.stdout();
    const stdin_fd = posix.STDIN_FILENO;
    var term = try posix.tcgetattr(stdin_fd);
    const original = term;
    term.lflag.ECHO = false;
    term.lflag.ICANON = false;
    try posix.tcsetattr(stdin_fd, .NOW, term);
    defer {
        const old_prot = io.swapCancelProtection(.blocked);
        posix.tcsetattr(stdin_fd, .NOW, original) catch {};
        _ = io.swapCancelProtection(old_prot);
    }
    try stdout.writeStreamingAll(io, "\x1b[6n");
    var buf: [32]u8 = undefined;
    const n = try File.stdin().readStreaming(io, &.{&buf});
    if (n <= 0) return 1;
    const res = buf[0..n];
    if (mem.indexOfScalar(u8, res, '[')) |start_idx| {
        if (mem.indexOfScalar(u8, res, ';')) |sep| {
            return fmt.parseInt(u16, res[start_idx + 1 .. sep], 10) catch 1;
        }
    }
    return 1;
}

pub fn syncDebugMode(enabled: bool, size_formatter: ?*const fn (buf: []u8, bytes: usize) []const u8) void {
    Store.debug_mode = enabled;
    if (size_formatter) |f| {
        Store.formatSize = f;
    }
}

pub fn start(
    io_group: *Group,
    base_allocator: Allocator,
    client: *Client,
    api_url: []const u8,
    session_start_ts_str: []const u8,
    drop_uid: u32,
    log_path: []const u8,
    agh_user: []const u8,
    diag: anytype,
    log_mode: Config.LogMode,
    scan_limit_mb: usize,
    polling_ms: u64,
    api_limit: u16,
    no_color: bool,
    catchup_limit: usize,
    config: *Config.AppConfig,
    environ: Environ,
) !void {
    const io = client.io;
    const stdout_file = File.stdout();
    const initial_winsize = getTermSize();
    const terminal_mode = try Mode.detect(io, stdout_file, no_color, false);
    var terminal_wrap_buf: [1024]u8 = undefined;
    var terminal_writer_wrapper = stdout_file.writer(io, &terminal_wrap_buf);
    var terminal_obj = Terminal{ .writer = &terminal_writer_wrapper.interface, .mode = terminal_mode };
    var mutable_diag_inst = diag;
    Store.initial_cursor_row = getCursorRow(io) catch 1;
    const has_mem_stats = comptime if (@hasField(@TypeOf(diag), "mem_enabled")) true else false;
    const diag_rows: u16 = if (has_mem_stats and diag.mem_enabled) blk: {
        var probe_work_buf: [4096]u8 = undefined;
        var probe_fba = FixedBufferAllocator.init(&probe_work_buf);
        var probe_coll = Collector.init(probe_fba.allocator(), &terminal_obj);
        defer probe_coll.deinit();
        mutable_diag_inst.appendMemoryStats(&probe_coll, &Store.scratch_fba, Store, io) catch {};
        break :blk @as(u16, @intCast(probe_coll.lines.items.len));
    } else 0;
    Store.footer_height = diag_rows;
    const reserved_rows: u16 = diag_rows + 2;
    defer if (has_mem_stats and diag.mem_enabled) {
        Store.io_mutex.lockUncancelable(io);
        defer Store.io_mutex.unlock(io);
        _ = linux.tcdrain(posix.STDOUT_FILENO);
        const final_ws = getTermSize();
        stdout_file.writeStreamingAll(io, "\x1b[r") catch {};
        var end_buf: [32]u8 = undefined;
        const end_seq = fmt.bufPrint(&end_buf, "\x1b[{d};1H", .{final_ws.row}) catch "\x1b[H";
        stdout_file.writeStreamingAll(io, end_seq) catch {};
        stdout_file.writeStreamingAll(io, "\x1b[K") catch {};
    };
    defer if (Store.session_cookie_len > 0) {
        Engine.performLogout(client, api_url, Store.session_cookie[0..Store.session_cookie_len]) catch |err| {
            if (Store.debug_mode) debug.print("\x1b[91m[DEBUG] Final session cleanup failed: {any}\x1b[0m\n", .{err});
        };
    };
    const DiagTaskWrapper = struct {
        fn run(io_p: Io, ctx_p: @TypeOf(diag), rows_p: u16, mode_p: Mode) void {
            Background.diagnosticTask(io_p, ctx_p, rows_p, mode_p);
        }
    }.run;
    if (has_mem_stats and diag.mem_enabled) {
        io_group.async(io, DiagTaskWrapper, .{ io, diag, diag_rows, terminal_mode });
    }
    var stop_heartbeat = false;
    io_group.async(io, Background.heartbeatTask, .{ io, api_url, &stop_heartbeat, base_allocator });
    var physical_parsed_count: usize = 0;
    if (log_mode != .disable) {
        const file_exists = blk: {
            const f = Dir.cwd().openFile(io, log_path, .{ .mode = .read_only }) catch {
                break :blk false;
            };
            f.close(io);
            break :blk true;
        };
        if (file_exists) {
            physical_parsed_count = Engine.streamFromFile(io, base_allocator, log_path, session_start_ts_str, stdout_file, initial_winsize.col, scan_limit_mb, no_color) catch |err| blk: {
                if (log_mode == .force) return err;
                if (Store.debug_mode) debug.print("\x1b[90m[DEBUG]\x1b[0m Physical log error: {any}\n", .{err});
                break :blk @as(usize, 0);
            };
        } else if (log_mode == .force) {
            return error.LogFileNotFound;
        }
    }
    _ = linux.tcdrain(posix.STDOUT_FILENO);
    stop_heartbeat = true;
    if (Store.should_exit) return;
    if (system.getuid() == 0) {
        if (system.setresuid(drop_uid, drop_uid, drop_uid) != 0) return error.PrivilegeDropFailed;
    }
    const base_limits = [_]u16{ 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000 };
    var limits_buf: [base_limits.len]u16 = undefined;
    var limits_count: usize = 0;
    for (base_limits) |limit| {
        if (limit < api_limit) {
            limits_buf[limits_count] = limit;
            limits_count += 1;
        } else break;
    }
    limits_buf[limits_count] = api_limit;
    limits_count += 1;
    const limits = limits_buf[0..limits_count];
    var anchor_established = (physical_parsed_count > 0);
    var limit_idx: usize = 0;
    var retry_wait_ms: u64 = 1000;
    var last_rotation_ts = Clock.real.now(io).toSeconds();
    const Bridge = struct {
        pub var io_inst: Io = undefined;
        pub var term_col: u16 = 0;
        pub var out_file: File = undefined;
        pub var processed_count: usize = 0;
        pub var start_pivot: []const u8 = undefined;
        pub var is_anchor_ready: *bool = undefined;
        pub var force_mode: bool = false;
        pub var no_color_static: bool = false;
        pub var total_in_chunk: usize = 0;
        pub var chunk_cursor: usize = 0;
        pub var has_logged_accept: bool = false;
        pub var diag_ctx_ptr: ?*@TypeOf(diag) = null;
        pub var reserved_rows_static: u16 = 0;
        pub var terminal_mode_static: Mode = undefined;
        pub var terminal_ptr: *Terminal = undefined;
        pub fn callback(alloc: Allocator, entry_json: []const u8) anyerror!void {
            if (Store.should_exit) return;
            const entry_ts = Json.getCompatibleValue(entry_json, .time) orelse return;
            if (Format.isExcessiveFuture(io_inst, entry_ts)) return;
            Store.state_lock.lockSharedUncancelable(io_inst);
            const anchor_ts = Store.last_seen_ts[0..Store.last_seen_ts_len];
            const custom_end_ts_active = Store.custom_end_ts[0..Store.custom_end_ts_len];
            const custom_end_ts_len = Store.custom_end_ts_len;
            if (custom_end_ts_len > 0) {
                if (mem.order(u8, entry_ts, custom_end_ts_active) == .gt) {
                    Store.state_lock.unlockShared(io_inst);
                    Store.should_exit = true;
                    return;
                }
            }
            if (!is_anchor_ready.*) {
                if (entry_ts.len >= 19 and mem.order(u8, entry_ts[0..19], start_pivot) == .lt) {
                    Store.state_lock.unlockShared(io_inst);
                    Store.state_lock.lockUncancelable(io_inst);
                    const safe_len = @min(entry_ts.len, Store.last_seen_ts.len);
                    @memcpy(Store.last_seen_ts[0..safe_len], entry_ts[0..safe_len]);
                    Store.last_seen_ts_len = safe_len;
                    Store.state_lock.unlock(io_inst);
                    chunk_cursor += 1;
                    return;
                }
                is_anchor_ready.* = true;
            }
            const cmp = mem.order(u8, entry_ts, anchor_ts);
            Store.state_lock.unlockShared(io_inst);
            const is_accepted = (force_mode and entry_ts.len >= 19 and mem.order(u8, entry_ts[0..19], start_pivot) != .lt) or cmp == .gt;
            if (Store.debug_mode) {
                const is_last = (total_in_chunk > 0 and chunk_cursor == total_in_chunk - 1);
                const should_log = (chunk_cursor == 0) or is_last or (is_accepted and !has_logged_accept);
                if (should_log) {
                    const status = if (is_accepted) "ACCEPT" else "SKIP  ";
                    debug.print("\x1b[90m[DEBUG]\x1b[0m Callback: {s} {s} ({s} vs {s})\n", .{ status, entry_ts, @tagName(cmp), anchor_ts });
                    if (is_accepted) has_logged_accept = true;
                }
            }
            if (is_accepted) {
                if (!Store.is_footer_fixed and diag_ctx_ptr != null) {
                    const cur_row = getCursorRow(io_inst) catch 1;
                    const ws = getTermSize();
                    if (cur_row + reserved_rows_static >= ws.row) {
                        Store.io_mutex.lockUncancelable(io_inst);
                        var scroll_storage: [2]Operation.Storage = undefined;
                        var batch = Batch.init(&scroll_storage);
                        var nl_buf: [64]u8 = undefined;
                        const nl_count = @min(nl_buf.len, reserved_rows_static);
                        @memset(nl_buf[0..nl_count], '\n');
                        const scroll_bottom = ws.row - reserved_rows_static;
                        var s_buf: [64]u8 = undefined;
                        const s_seq = fmt.bufPrint(&s_buf, "\x1b[1;{d}r\x1b[{d};1H", .{ scroll_bottom, scroll_bottom }) catch "";
                        _ = batch.add(.{ .file_write_streaming = .{ .file = out_file, .data = &.{nl_buf[0..nl_count]} } });
                        _ = batch.add(.{ .file_write_streaming = .{ .file = out_file, .data = &.{s_seq} } });
                        batch.awaitConcurrent(io_inst, .none) catch {};
                        Store.is_footer_fixed = true;
                        Store.io_mutex.unlock(io_inst);
                    }
                }
                if (!Store.has_drawn_boundary and Store.session_start_anchor_len > 0) {
                    const is_historical_start = mem.order(u8, start_pivot, Store.session_start_anchor[0..19]) == .lt;
                    if (is_historical_start) {
                        if (mem.order(u8, entry_ts, Store.session_start_anchor[0..Store.session_start_anchor_len]) != .lt) {
                            Store.io_mutex.lockUncancelable(io_inst);
                            var b_buf: [1024]u8 = undefined;
                            const b_len = @min(term_col, b_buf.len - 1);
                            @memset(b_buf[0..b_len], '-');
                            b_buf[b_len] = '\n';
                            try out_file.writeStreamingAll(io_inst, b_buf[0 .. b_len + 1]);
                            Store.io_mutex.unlock(io_inst);
                            Store.has_drawn_boundary = true;
                        }
                    }
                }
                Store.state_lock.lockUncancelable(io_inst);
                const safe_len = @min(entry_ts.len, Store.last_seen_ts.len);
                @memcpy(Store.last_seen_ts[0..safe_len], entry_ts[0..safe_len]);
                Store.last_seen_ts_len = safe_len;
                Store.state_lock.unlock(io_inst);
                try LogLine.displayLogItemRaw(terminal_ptr, io_inst, alloc, entry_json, term_col, out_file, true, no_color_static);
                processed_count += 1;
                if (!Store.is_footer_fixed and diag_ctx_ptr != null) {
                    Store.io_mutex.lockUncancelable(io_inst);
                    const ws = getTermSize();
                    var f_buf: [8192]u8 = undefined;
                    var f_fba = FixedBufferAllocator.init(&f_buf);
                    var t_wrap_buf: [1024]u8 = undefined;
                    var t_writer_wrapper = out_file.writer(io_inst, &t_wrap_buf);
                    var t_obj = Terminal{ .writer = &t_writer_wrapper.interface, .mode = terminal_mode_static };
                    var f_coll = Collector.init(f_fba.allocator(), &t_obj);
                    defer f_coll.deinit();
                    f_coll.ansi_visible = diag_ctx_ptr.?.ansi_visible;
                    Store.state_lock.lockSharedUncancelable(io_inst);
                    diag_ctx_ptr.?.appendMemoryStats(&f_coll, &Store.scratch_fba, Store, io_inst) catch {};
                    Store.state_lock.unlockShared(io_inst);
                    var out_buf: [16384]u8 = undefined;
                    var f_writer = Writer.fixed(&out_buf);
                    f_writer.writeAll("\x1b[?25l\x1b7\r") catch {};
                    f_writer.print("{s}", .{Format.clr_dim}) catch {};
                    f_writer.splatByteAll('-', ws.col) catch {};
                    f_writer.print("{s}\n", .{Format.clr_reset}) catch {};
                    for (f_coll.lines.items) |line| {
                        f_writer.print("\x1b[K{s}\n", .{line.text}) catch {};
                    }
                    f_writer.writeAll("\x1b8\x1b[?25h") catch {};
                    try out_file.writeStreamingAll(io_inst, f_writer.buffered());
                    Store.io_mutex.unlock(io_inst);
                }
            }
            chunk_cursor += 1;
        }
    };
    Bridge.terminal_ptr = &terminal_obj;
    Bridge.io_inst = io;
    Bridge.term_col = initial_winsize.col;
    Bridge.out_file = stdout_file;
    Bridge.start_pivot = session_start_ts_str[0..19];
    Bridge.is_anchor_ready = &anchor_established;
    Bridge.no_color_static = no_color;
    Bridge.reserved_rows_static = reserved_rows;
    Bridge.terminal_mode_static = terminal_mode;
    if (has_mem_stats and diag.mem_enabled) {
        Bridge.diag_ctx_ptr = &mutable_diag_inst;
    }
    while (!Store.should_exit) {
        try io.checkCancel();
        const now = Clock.real.now(io).toSeconds();
        if (now - last_rotation_ts >= constants.SESSION_ROTATION_S or Store.session_trash_count > 0) {
            const saved_bundle = client.ca_bundle;
            client.ca_bundle = .empty;
            client.deinit();
            Store.net_client_fba.reset();
            client.* = Client{
                .allocator = Store.net_client_fba.allocator(),
                .io = io,
                .ca_bundle = saved_bundle,
                .now = Clock.real.now(io),
            };
            if (now - last_rotation_ts >= constants.SESSION_ROTATION_S and Store.session_cookie_len > 0) {
                if (Store.session_trash_count < Store.session_trash.len) {
                    var trash = &Store.session_trash[Store.session_trash_count];
                    @memcpy(trash.cookie[0..Store.session_cookie_len], Store.session_cookie[0..Store.session_cookie_len]);
                    trash.len = Store.session_cookie_len;
                    Store.session_trash_count += 1;
                    Store.session_cookie_len = 0;
                }
            }
            var t_idx: usize = 0;
            while (t_idx < Store.session_trash_count) {
                const t_sess = &Store.session_trash[t_idx];
                Engine.performLogout(client, api_url, t_sess.cookie[0..t_sess.len]) catch {
                    t_idx += 1;
                    continue;
                };
                if (t_idx + 1 < Store.session_trash_count) {
                    const remain = Store.session_trash_count - (t_idx + 1);
                    mem.copyBackwards(Store.AbandonedSession, Store.session_trash[t_idx .. t_idx + remain], Store.session_trash[t_idx + 1 .. t_idx + 1 + remain]);
                }
                Store.session_trash_count -= 1;
            }
            if (now - last_rotation_ts >= constants.SESSION_ROTATION_S) {
                Store.net_client_fba.reset();
                var rot_scratch: [8192]u8 align(4096) = undefined;
                defer crypto.secureZero(u8, &rot_scratch);
                var rot_fba = FixedBufferAllocator.init(&rot_scratch);
                if (Crypt.GpgDecrypter.readFromKeyring(rot_fba.allocator(), Store.keyring_key_name)) |password| {
                    defer crypto.secureZero(u8, @constCast(password));
                    var l_url_buf: [512]u8 = undefined;
                    const login_endpoint = try fmt.bufPrint(&l_url_buf, "{s}/login", .{api_url});
                    if (Engine.performLogin(client, login_endpoint, agh_user, password, rot_fba.allocator())) |_| {
                        last_rotation_ts = now;
                    } else |err| {
                        if (Store.debug_mode) debug.print("\x1b[91m[DEBUG] Session rotation failed: {any}. Retrying soon...\x1b[0m\n", .{err});
                    }
                } else |err| {
                    if (Store.debug_mode) debug.print("\x1b[91m[DEBUG] Session rotation skipped: Could not read password from Keyring: {any}\x1b[0m\n", .{err});
                }
            }
        }
        var query_url_buf: [512]u8 = undefined;
        const current_limit = limits[limit_idx];
        const url = try fmt.bufPrint(&query_url_buf, "{s}/querylog?limit={d}", .{ api_url, current_limit });
        const raw_data = Engine.fetchApiToBuffer(client, url, "", Store.scratch_buffer) catch |err| {
            if (Store.should_exit) break;
            if (Store.debug_mode) {
                debug.print("\x1b[93m[DEBUG] API Access Error: {any}. Retrying in {d}ms...\x1b[0m\n", .{ err, retry_wait_ms });
            }
            const is_fatal_network_error = switch (err) {
                error.ConnectionRefused,
                error.HostUnreachable,
                error.NetworkUnreachable,
                error.Timeout,
                error.ConnectionResetByPeer,
                error.NetworkDown,
                error.Unauthorized,
                error.ServiceUnavailable,
                error.HttpConnectionClosing,
                error.ApiRequestRejected,
                => true,
                else => false,
            };
            if (is_fatal_network_error) {
                if (Store.session_cookie_len > 0) {
                    if (Store.session_trash_count < Store.session_trash.len) {
                        var trash = &Store.session_trash[Store.session_trash_count];
                        @memcpy(trash.cookie[0..Store.session_cookie_len], Store.session_cookie[0..Store.session_cookie_len]);
                        trash.len = Store.session_cookie_len;
                        Store.session_trash_count += 1;
                        Store.session_cookie_len = 0;
                    }
                }
                const saved_bundle = client.ca_bundle;
                client.ca_bundle = .empty;
                client.deinit();
                Store.net_client_fba.reset();
                client.* = Client{ .allocator = Store.net_client_fba.allocator(), .io = io, .ca_bundle = saved_bundle, .now = Clock.real.now(io) };
                if (err == error.Unauthorized) {
                    var login_url_buf: [512]u8 = undefined;
                    const login_endpoint = try fmt.bufPrint(&login_url_buf, "{s}/login", .{api_url});
                    Auth.ensureAuthenticated(&terminal_obj, io, base_allocator, base_allocator, client, config, login_endpoint, environ) catch {
                        AnchorLogic.waitPrecision(io, retry_wait_ms);
                        retry_wait_ms = @min(retry_wait_ms * 2, 30000);
                        continue;
                    };
                    retry_wait_ms = 1000;
                    continue;
                }
            }
            AnchorLogic.waitPrecision(io, retry_wait_ms);
            retry_wait_ms = @min(retry_wait_ms * 2, 30000);
            continue;
        };
        retry_wait_ms = 1000;
        Store.state_lock.lockSharedUncancelable(io);
        const last_seen_slice = Store.last_seen_ts[0..Store.last_seen_ts_len];
        const has_anchor = mem.indexOf(u8, raw_data, last_seen_slice) != null;
        Store.state_lock.unlockShared(io);
        if (!has_anchor) {
            if (limit_idx < limits.len - 1) {
                limit_idx += 1;
                continue;
            } else {
                try AnchorLogic.handleAnchorLoss(io, client, api_url, api_limit, catchup_limit, &query_url_buf, Bridge);
                if (Store.should_exit) break;
                limit_idx = limits.len - 1;
                AnchorLogic.waitPrecision(io, 500);
                continue;
            }
        }
        Bridge.processed_count = 0;
        Bridge.force_mode = false;
        Bridge.total_in_chunk = mem.count(u8, raw_data, "\"time\":");
        Bridge.chunk_cursor = 0;
        Bridge.has_logged_accept = false;
        try Json.processJsonBulkReverse(raw_data, Bridge.callback);
        if (Store.should_exit) break;
        limit_idx = if (Bridge.processed_count >= current_limit) @as(usize, limits.len - 1) else @as(usize, 0);
        AnchorLogic.waitPrecision(io, polling_ms);
    }
}
