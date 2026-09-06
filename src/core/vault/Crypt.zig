const std = @import("std");
const c_std = std.c;
const posix = std.posix;
const system = posix.system;
const Io = std.Io;
const fs = std.fs;
const mem = std.mem;
const fmt = std.fmt;
const heap = std.heap;
const debug = std.debug;
const crypto = std.crypto;
const process = std.process;
const Dir = Io.Dir;
const Writer = Io.Writer;
const Duration = Io.Duration;
const Stream = Io.net.Stream;
const UnixAddress = Io.net.UnixAddress;
const Environ = process.Environ;
const Alignment = mem.Alignment;
const Allocator = mem.Allocator;

pub const Store = @import("../../data/Store.zig");
const Keyring = @import("Keyring.zig");

const c = @cImport({
    @cInclude("gcrypt.h");
    @cInclude("gpgme.h");
});

pub const RetryConfig = union(enum) {
    infinite: void,
    once: void,
    timeout: usize,
};

pub const KeyringOwner = enum {
    root,
    sudo_user,
};

pub const KeyringConfig = struct {
    key_name: []const u8,
    owner: KeyringOwner,
};

pub const GpgDecrypter = struct {
    const GPG_AGENT_SOCK = "gnupg/S.gpg-agent";

    extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

    fn copyZ(dest: []u8, src: []const u8) [*:0]u8 {
        const len = @min(dest.len - 1, src.len);
        @memcpy(dest[0..len], src[0..len]);
        dest[len] = 0;
        return @ptrCast(dest.ptr);
    }

    const SubkeyMirror = extern struct {
        next: ?*@This(),
        _bits: u32,
        pubkey_algo: c_uint,
        length: c_uint,
        keyid: [*c]const u8,
        _keyid: [17]u8,
        fpr: [*c]const u8,
        timestamp: c_long,
        expires: c_long,
        card_number: [*c]const u8,
        curve: [*c]const u8,
        keygrip: [*c]const u8,
        v5fpr: [*c]const u8,
    };

    const KeyMirror = extern struct {
        _refs: c_uint,
        _bits: u32,
        protocol: c_int,
        issuer_serial: [*c]const u8,
        issuer_name: [*c]const u8,
        chain_id: [*c]const u8,
        owner_trust: c_int,
        subkeys: ?*SubkeyMirror,
    };

    fn getPassStoreDir(allocator: Allocator, environ: Environ, home_dir: []const u8) ![]const u8 {
        if (environ.getPosix("PASSWORD_STORE_DIR")) |psd| {
            return allocator.dupe(u8, psd);
        }
        return fs.path.resolve(allocator, &.{ home_dir, ".password-store" });
    }

    pub fn getPassword(
        allocator: Allocator,
        entry_name: []const u8,
        config: RetryConfig,
        stay_root: bool,
        keyring_opt: ?KeyringConfig,
        environ: Environ,
        io: Io,
    ) ![]const u8 {
        const sudo_user_ptr = environ.getPosix("SUDO_USER");

        const pw_ptr = if (sudo_user_ptr) |u| blk: {
            var u_buf: [128]u8 = undefined;
            break :blk c_std.getpwnam(copyZ(&u_buf, u));
        } else c_std.getpwuid(system.getuid());

        const pw = pw_ptr orelse return error.UserNotFound;
        const home_dir = mem.span(pw.dir orelse return error.UserHomeNotFound);

        if (!stay_root) {
            const target_uid = pw.uid;
            const user_name = pw.name orelse return error.UserNameNotFound;
            var rd_buf: [64]u8 = undefined;
            const rd_str = try fmt.bufPrintZ(&rd_buf, "/run/user/{d}", .{target_uid});

            _ = setenv("HOME", home_dir.ptr, 1);
            _ = setenv("XDG_RUNTIME_DIR", rd_str.ptr, 1);
            _ = setenv("USER", user_name, 1);
        }

        const pass_store_dir = try getPassStoreDir(allocator, environ, home_dir);
        defer allocator.free(pass_store_dir);

        const grip_raw = try findTargetGripViaGpgme(io, allocator, home_dir, pass_store_dir);
        defer allocator.free(grip_raw);

        var remaining_retries: usize = if (config == .timeout) config.timeout else 0;

        while (true) {
            var agent_stream = try connectToAgent(io, pw.uid, stay_root);
            defer agent_stream.close(io);

            var all_ok = true;
            var grip_it = mem.splitScalar(u8, grip_raw, ',');
            while (grip_it.next()) |grip| {
                const trimmed = mem.trim(u8, grip, " \r\n");
                if (trimmed.len == 0) continue;

                var writer_wrapper = agent_stream.writer(io, &.{});
                writer_wrapper.interface.end = 0;
                const writer = &writer_wrapper.interface;

                try writer.print("KEYINFO {s}\n", .{trimmed});

                var r_buf: [1024]u8 = undefined;
                var reader_wrapper = agent_stream.reader(io, &r_buf);
                reader_wrapper.interface.seek = 0;
                reader_wrapper.interface.end = 0;
                const reader = &reader_wrapper.interface;

                var status: u8 = '-';
                while (true) {
                    const res = try reader.takeDelimiter('\n');
                    if (res == null) break;
                    const resp = res.?;

                    if (mem.indexOf(u8, resp, "S KEYINFO")) |_| {
                        var fields = mem.tokenizeAny(u8, resp, " \r\n");
                        var count: usize = 0;
                        while (fields.next()) |f| : (count += 1) {
                            if (count == 6) {
                                status = f[0];
                                break;
                            }
                        }
                    }
                    if (mem.indexOf(u8, resp, "OK") != null or mem.indexOf(u8, resp, "ERR") != null) break;
                }
                if (status != '1') all_ok = false;
            }

            if (all_ok) {
                const password = try decryptGpgDirect(io, allocator, pw, pass_store_dir, entry_name, stay_root);
                if (keyring_opt) |k_cfg| try storeToKeyring(password, k_cfg, pw.uid);
                return password;
            }

            switch (config) {
                .once => return error.CacheNotReady,
                .timeout => {
                    if (remaining_retries == 0) return error.RetryTimeout;
                    remaining_retries -= 1;
                },
                .infinite => {},
            }
            try io.sleep(Duration.fromSeconds(1), .awake);
        }
    }

    pub fn storeToKeyring(password: []const u8, config: KeyringConfig, user_uid: u32) !void {
        const current_uid = system.getuid();
        const target_uid = if (config.owner == .sudo_user) user_uid else 0;

        if (Store.debug_mode) {
            debug.print("\x1b[90m[DEBUG]\x1b[0m Keyring: Store request (Current UID: {d}, Target: {d})\n", .{ current_uid, target_uid });
        }

        if (current_uid == 0 and target_uid != current_uid) {
            const res = system.setresuid(target_uid, target_uid, 0);
            if (res != 0) {
                if (Store.debug_mode) {
                    debug.print("\x1b[91m[DEBUG]\x1b[0m Keyring: Failed to drop privileges for storage (rc: {d})\n", .{res});
                }
                return error.SetResUidFailed;
            }
        }
        defer if (current_uid == 0 and target_uid != current_uid) {
            _ = system.setresuid(0, 0, 0);
        };

        var desc_buf: [128]u8 = undefined;
        const desc_z = copyZ(&desc_buf, config.key_name);

        const key_rc = Keyring.add_key("user", desc_z, password.ptr, password.len, Keyring.KEY_SPEC_PROCESS_KEYRING);

        if (key_rc < 0) {
            if (Store.debug_mode) {
                debug.print("\x1b[91m[DEBUG]\x1b[0m Keyring: add_key failed. Error code: {d}\n", .{key_rc});
            }
            return error.KernelKeyringAddFailed;
        }

        _ = Keyring.setPermission(key_rc, Keyring.POSSESSOR_ONLY_READ_SEARCH_DELETE);

        if (Store.debug_mode) {
            debug.print("\x1b[92m[DEBUG]\x1b[0m Keyring: Successfully stored password in Process Keyring (ID: {d})\n", .{key_rc});
        }
    }

    pub fn readFromKeyring(allocator: Allocator, key_name: []const u8) ![]const u8 {
        var desc_buf: [128]u8 = undefined;
        const desc_z = copyZ(&desc_buf, key_name);

        const key_id = Keyring.searchKey(desc_z);
        if (key_id < 0) return error.KeyNotFoundInKeyring;

        const size_res = Keyring.readKey(key_id, null, 0);
        if (size_res < 0) return error.KeyReadError;
        const size = @as(usize, @intCast(size_res));

        const buffer = try allocator.alignedAlloc(u8, Alignment.fromByteUnits(heap.page_size_min), size);
        errdefer allocator.free(buffer);

        try process.lockMemory(buffer, .{});

        const actual_read = Keyring.readKey(key_id, buffer.ptr, buffer.len);
        if (actual_read < 0) {
            process.unlockMemory(buffer) catch {};
            allocator.free(buffer);
            return error.KeyReadError;
        }

        return buffer;
    }

    pub fn removeFromKeyring(key_name: []const u8) !void {
        var desc_buf: [128]u8 = undefined;
        const desc_z = copyZ(&desc_buf, key_name);
        const key_id = Keyring.searchKey(desc_z);
        if (key_id >= 0) _ = Keyring.revokeKey(key_id);
    }

    fn findTargetGripViaGpgme(io: Io, allocator: Allocator, home_dir: []const u8, pass_store_dir: []const u8) ![]const u8 {
        const gpg_id_path = try fs.path.resolve(allocator, &.{ pass_store_dir, ".gpg-id" });
        defer allocator.free(gpg_id_path);

        var target_hex_buf: [128]u8 = undefined;
        const target_hex = blk: {
            const file = Dir.cwd().openFile(io, gpg_id_path, .{ .mode = .read_only }) catch {
                break :blk try getMasterFingerprint(io, home_dir, &target_hex_buf);
            };
            defer file.close(io);
            const n = try file.readPositional(io, &.{&target_hex_buf}, 0);
            if (n <= 0) return error.KeyReadError;
            var it = mem.splitScalar(u8, target_hex_buf[0..n], '\n');
            break :blk mem.trim(u8, it.first(), " \r\n");
        };

        const target_hex_z = try allocator.dupeZ(u8, target_hex);
        defer allocator.free(target_hex_z);

        const gpg_home_path = try fs.path.resolve(allocator, &.{ home_dir, ".gnupg" });
        defer allocator.free(gpg_home_path);
        const gpg_home_z = try allocator.dupeZ(u8, gpg_home_path);
        defer allocator.free(gpg_home_z);

        _ = c.gpgme_check_version(null);
        try checkGpgError(c.gpgme_set_engine_info(c.GPGME_PROTOCOL_OpenPGP, null, @ptrCast(gpg_home_z.ptr)), "set_engine");
        var ctx: c.gpgme_ctx_t = undefined;
        try checkGpgError(c.gpgme_new(&ctx), "new_ctx");
        defer c.gpgme_release(ctx);
        try checkGpgError(c.gpgme_op_keylist_start(ctx, target_hex_z.ptr, 1), "keylist_start");
        defer _ = c.gpgme_op_keylist_end(ctx);

        var grip_list_buf: [2048]u8 = undefined;
        var writer = Writer.fixed(&grip_list_buf);

        var key_handle: c.gpgme_key_t = undefined;
        while (c.gpgme_op_keylist_next(ctx, &key_handle) == 0) {
            const kh = key_handle.?;
            defer c.gpgme_key_unref(kh);

            const k = @as(*const KeyMirror, @ptrCast(@alignCast(kh)));
            var subkey = k.subkeys;
            while (subkey) |s| {
                if ((s._bits & 0x10) != 0) {
                    if (s.keygrip) |grip| {
                        if (writer.buffered().len > 0) try writer.writeByte(',');
                        try writer.writeAll(mem.span(grip));
                    }
                }
                subkey = s.next;
            }
        }
        if (writer.buffered().len == 0) return error.KeyGripNotFoundInBinary;
        return try allocator.dupe(u8, writer.buffered());
    }

    fn decryptGpgDirect(io: Io, allocator: Allocator, pw: *const c_std.passwd, pass_store_dir: []const u8, entry: []const u8, stay_root: bool) ![]const u8 {
        _ = io;
        const was_root = system.getuid() == 0;
        const should_downgrade = was_root and !stay_root;

        if (should_downgrade) {
            if (system.setresuid(pw.uid, pw.uid, 0) != 0) return error.SetResUidFailed;
        }
        defer if (should_downgrade) {
            _ = system.setresuid(0, 0, 0);
        };

        const home_dir = mem.span(pw.dir orelse return error.UserHomeNotFound);
        const entry_file = try fmt.allocPrint(allocator, "{s}.gpg", .{entry});
        defer allocator.free(entry_file);
        const entry_path = try fs.path.resolve(allocator, &.{ pass_store_dir, entry_file });
        defer allocator.free(entry_path);
        const entry_path_z = try allocator.dupeZ(u8, entry_path);
        defer allocator.free(entry_path_z);

        const gpg_home_path = try fs.path.resolve(allocator, &.{ home_dir, ".gnupg" });
        defer allocator.free(gpg_home_path);
        const gpg_home_z = try allocator.dupeZ(u8, gpg_home_path);
        defer allocator.free(gpg_home_z);

        _ = c.gpgme_check_version(null);
        try checkGpgError(c.gpgme_set_engine_info(c.GPGME_PROTOCOL_OpenPGP, null, @ptrCast(gpg_home_z.ptr)), "decrypt_engine");
        var ctx: c.gpgme_ctx_t = undefined;
        try checkGpgError(c.gpgme_new(&ctx), "decrypt_ctx");
        defer c.gpgme_release(ctx);
        _ = c.gpgme_set_pinentry_mode(ctx, c.GPGME_PINENTRY_MODE_ERROR);

        var input: c.gpgme_data_t = undefined;
        try checkGpgError(c.gpgme_data_new_from_file(&input, @ptrCast(entry_path_z.ptr), 1), "data_file");
        defer c.gpgme_data_release(input);
        var output: c.gpgme_data_t = undefined;
        try checkGpgError(c.gpgme_data_new(&output), "data_out");
        defer c.gpgme_data_release(output);

        try checkGpgError(c.gpgme_op_decrypt(ctx, input, output), "op_decrypt");
        const size = @as(usize, @intCast(c.gpgme_data_seek(output, 0, 2)));
        _ = c.gpgme_data_seek(output, 0, 0);

        const temp_buffer = try allocator.alignedAlloc(u8, Alignment.fromByteUnits(heap.page_size_min), size);
        try process.lockMemory(temp_buffer, .{});
        defer {
            crypto.secureZero(u8, temp_buffer);
            process.unlockMemory(temp_buffer) catch {};
            allocator.free(temp_buffer);
        }
        _ = c.gpgme_data_read(output, temp_buffer.ptr, size);
        return try allocator.dupe(u8, mem.trim(u8, temp_buffer, " \n\r"));
    }

    fn checkGpgError(err: c.gpgme_error_t, context: []const u8) !void {
        if (err != 0) {
            debug.print("❌ GPGME Error [{s}]: {s}\n", .{ context, mem.span(c.gpgme_strerror(err)) });
            return error.GpgmeOperationFailed;
        }
    }

    pub fn connectToAgent(io: Io, target_uid: u32, stay_root: bool) !Stream {
        const was_root = system.getuid() == 0;
        const should_downgrade = was_root and !stay_root;

        if (should_downgrade) {
            if (system.setresuid(target_uid, target_uid, 0) != 0) return error.SetResUidFailed;
        }
        defer if (should_downgrade) {
            _ = system.setresuid(0, 0, 0);
        };

        var sock_path_buf: [128]u8 = undefined;
        var f = Writer.fixed(&sock_path_buf);
        f.print("/run/user/{d}/gnupg/S.gpg-agent", .{target_uid}) catch {};
        const sock_path = f.buffered();

        const ua = try UnixAddress.init(sock_path);
        const stream = try ua.connect(io);

        var greeting_buf: [256]u8 = undefined;
        var r_obj = stream.reader(io, &greeting_buf);
        _ = try r_obj.interface.takeDelimiter('\n');

        return stream;
    }

    fn getMasterFingerprint(io: Io, home_dir: []const u8, i_out_buf: []u8) ![]u8 {
        var path_buf: [512]u8 = undefined;
        var f = Writer.fixed(&path_buf);
        f.print("{s}/.gnupg/gpg.conf", .{home_dir}) catch {};
        const conf_path = f.buffered();

        const file = try Dir.cwd().openFile(io, conf_path, .{ .mode = .read_only });
        defer file.close(io);

        var content_buf: [4096]u8 = undefined;
        const n = try file.readPositional(io, &.{&content_buf}, 0);
        if (n <= 0) return error.DefaultKeyNotFound;
        var it = mem.splitScalar(u8, content_buf[0..n], '\n');
        while (it.next()) |line| {
            const trimmed = mem.trim(u8, line, " \r\n");
            if (mem.startsWith(u8, trimmed, "default-key")) {
                var parts = mem.tokenizeScalar(u8, trimmed, ' ');
                _ = parts.next();
                if (parts.next()) |val| {
                    const clean_val = mem.trim(u8, val, " ");
                    const copy_len = @min(clean_val.len, i_out_buf.len);
                    @memcpy(i_out_buf[0..copy_len], clean_val[0..copy_len]);
                    return i_out_buf[0..copy_len];
                }
            }
        }
        return error.DefaultKeyNotFound;
    }
};
