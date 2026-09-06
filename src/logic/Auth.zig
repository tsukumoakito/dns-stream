const std = @import("std");
const c_std = std.c;
const posix = std.posix;
const system = posix.system;
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const heap = std.heap;
const http = std.http;
const debug = std.debug;
const crypto = std.crypto;
const process = std.process;
const File = Io.File;
const Terminal = Io.Terminal;
const Duration = Io.Duration;
const Mode = Io.Terminal.Mode;
const Client = http.Client;
const Environ = process.Environ;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

const Crypt = @import("../core/vault/Crypt.zig");
const Store = @import("../data/Store.zig");
const Engine = @import("../logic/Engine.zig");
const Format = @import("../view/Format.zig");
const Config = @import("Config.zig");

fn isNetworkError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.Timeout,
        error.ConnectionResetByPeer,
        error.NetworkDown,
        error.ServiceUnavailable,
        error.HttpConnectionClosing,
        => true,
        else => false,
    };
}

pub fn ensureAuthenticated(
    terminal: *Terminal,
    io: Io,
    allocator: Allocator,
    arena: Allocator,
    http_client: *Client,
    config: *Config.AppConfig,
    login_endpoint: []const u8,
    environ: Environ,
) !void {
    _ = terminal;
    var interactive_retries: usize = 0;
    var prompted_pass: ?[]const u8 = null;
    const stdout_file = File.stdout();

    while (!Store.should_exit) {
        try io.checkCancel();

        var password: []const u8 = undefined;
        var must_free = false;
        var from_keyring = false;

        const keyring_pass = Crypt.GpgDecrypter.readFromKeyring(allocator, Store.keyring_key_name) catch null;

        if (keyring_pass) |p| {
            password = p;
            must_free = true;
            from_keyring = true;
        } else {
            if (config.pass) |p| {
                password = p;
            } else if (prompted_pass) |p| {
                password = p;
            } else if (config.vault_path) |vp| {
                password = Crypt.GpgDecrypter.getPassword(allocator, vp, .once, false, null, environ, io) catch |err| {
                    if (isNetworkError(err)) return err;

                    try io.sleep(Duration.fromSeconds(1), .awake);
                    continue;
                };
                must_free = true;
            } else {
                if (interactive_retries >= 2) {
                    try stdout_file.writeStreamingAll(io, Format.clr_red ++ "❌ Too many failed attempts." ++ Format.clr_reset ++ "\n");
                    return error.AuthenticationFailed;
                }
                interactive_retries += 1;
                prompted_pass = try promptPassword(io, arena, config.user, interactive_retries);
                if (prompted_pass == null or Store.should_exit) break;
                password = prompted_pass.?;
            }
        }

        if (password.len == 0) {
            if (must_free) allocator.free(password);
            prompted_pass = null;
            continue;
        }

        const page_size = heap.page_size_min;
        const addr = @intFromPtr(password.ptr);
        const page_start = mem.alignBackward(usize, addr, page_size);
        const page_end = mem.alignForward(usize, addr + password.len, page_size);
        const lock_len = page_end - page_start;
        const locked_mem = @as([]align(heap.page_size_min) const u8, @alignCast(@as([*]const u8, @ptrFromInt(page_start))[0..lock_len]));

        try process.lockMemory(locked_mem, .{});

        const login_res = Engine.performLogin(http_client, login_endpoint, config.user, password, allocator);

        if (login_res) |_| {
            if (!from_keyring) {
                const keyring_cfg = Crypt.KeyringConfig{ .key_name = Store.keyring_key_name, .owner = .sudo_user };
                const sudo_uid = if (environ.getPosix("SUDO_USER")) |u_ptr| blk: {
                    var u_buf: [128]u8 = undefined;
                    const u_z = fmt.bufPrintZ(&u_buf, "{s}", .{u_ptr}) catch break :blk system.getuid();
                    const pw = c_std.getpwnam(u_z);
                    break :blk if (pw) |ptr| ptr.uid else system.getuid();
                } else system.getuid();

                _ = Crypt.GpgDecrypter.storeToKeyring(password, keyring_cfg, sudo_uid) catch |err| {
                    if (Store.debug_mode) debug.print("\x1b[90m[DEBUG]\x1b[0m Keyring persistence failed: {any}\n", .{err});
                };
            }

            const old_prot = io.swapCancelProtection(.blocked);
            defer _ = io.swapCancelProtection(old_prot);

            if (must_free) {
                crypto.secureZero(u8, @constCast(password));
                process.unlockMemory(locked_mem) catch {};
                allocator.free(password);
            }
            break;
        } else |err| {
            const old_prot = io.swapCancelProtection(.blocked);
            defer _ = io.swapCancelProtection(old_prot);

            if (from_keyring) {
                _ = Crypt.GpgDecrypter.removeFromKeyring(Store.keyring_key_name) catch {};
            }

            if (must_free) {
                crypto.secureZero(u8, @constCast(password));
                process.unlockMemory(locked_mem) catch {};
                allocator.free(password);
            }

            if (isNetworkError(err)) return err;

            if (config.pass == null and config.vault_path == null) {
                try stdout_file.writeStreamingAll(io, Format.clr_red ++ "❌ Login failed. Please try again." ++ Format.clr_reset ++ "\n");
                prompted_pass = null;
            }

            if (Store.debug_mode) {
                debug.print("\x1b[90m[DEBUG]\x1b[0m Authentication attempt failed: {any}\n", .{err});
            }

            if (Store.should_exit) break;
            try io.sleep(Duration.fromSeconds(1), .awake);
        }
    }

    if (Store.should_exit) return error.OperationAborted;
}

fn promptPassword(io: Io, arena: Allocator, user: []const u8, attempt: usize) !?[]const u8 {
    const stdout_file = File.stdout();
    const stdin_file = File.stdin();

    try stdout_file.writeStreamingAll(io, "\n" ++ Format.clr_bold ++ "🔑 Authentication Required (Attempt ");
    var att_buf: [2]u8 = undefined;
    const att_slice = try fmt.bufPrint(&att_buf, "{d}", .{attempt});
    try stdout_file.writeStreamingAll(io, att_slice);
    try stdout_file.writeStreamingAll(io, "/2)" ++ Format.clr_reset ++ "\nPassword for ");
    try stdout_file.writeStreamingAll(io, user);
    try stdout_file.writeStreamingAll(io, ": ");

    const term_mode = try Mode.detect(io, stdin_file, false, false);
    const original_mode = term_mode;

    if (term_mode == .escape_codes) {
        try stdout_file.writeStreamingAll(io, "\x1b[8m");
    }

    var pass_list: ArrayList(u8) = .empty;
    defer pass_list.deinit(arena);

    var char_buf: [1]u8 = undefined;

    while (!Store.should_exit) {
        const n = try stdin_file.readStreaming(io, &.{&char_buf});
        if (n == 0) break;

        const char = char_buf[0];
        if (char == '\n' or char == '\r') break;
        if (char == 127 or char == 8) {
            if (pass_list.items.len > 0) _ = pass_list.pop();
            continue;
        }
        if (char == 3) {
            Store.should_exit = true;
            break;
        }

        try pass_list.append(arena, char);
    }

    if (original_mode == .escape_codes) {
        try stdout_file.writeStreamingAll(io, "\x1b[28m");
    }

    try stdout_file.writeStreamingAll(io, "\n");

    if (Store.should_exit or pass_list.items.len == 0) {
        return null;
    }

    const result = try arena.dupe(u8, pass_list.items);
    crypto.secureZero(u8, pass_list.items);
    return result;
}
