const std = @import("std");
const linux = std.os.linux;

pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

pub const KEYCTL_SETPERM: i32 = 5;
pub const KEYCTL_REVOKE: i32 = 3;
pub const KEYCTL_SEARCH: i32 = 10;
pub const KEYCTL_READ: i32 = 11;

pub const POSSESSOR_ONLY_READ_SEARCH_DELETE: u32 = 0x2b000000;

pub fn specId(id: i32) usize {
    return @as(usize, @bitCast(@as(isize, id)));
}

pub fn add_key(type_str: [*:0]const u8, description: [*:0]const u8, payload: ?*const anyopaque, plen: usize, keyring_id: i32) i32 {
    const rc = linux.syscall5(
        .add_key,
        @intFromPtr(type_str),
        @intFromPtr(description),
        @intFromPtr(payload),
        plen,
        specId(keyring_id),
    );
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @as(i32, @truncate(@as(isize, @bitCast(rc))));
}

pub fn keyctl(operation: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) i32 {
    const rc = linux.syscall5(
        .keyctl,
        @as(usize, @intCast(operation)),
        arg2,
        arg3,
        arg4,
        arg5,
    );
    if (linux.errno(rc) != .SUCCESS) return -1;
    return @as(i32, @truncate(@as(isize, @bitCast(rc))));
}

pub fn searchKey(key_name: [*:0]const u8) i32 {
    const type_ptr: [*:0]const u8 = "user";
    const res = keyctl(
        KEYCTL_SEARCH,
        specId(KEY_SPEC_SESSION_KEYRING),
        @intFromPtr(type_ptr),
        @intFromPtr(key_name),
        0,
    );
    if (res >= 0) return res;

    return keyctl(
        KEYCTL_SEARCH,
        specId(KEY_SPEC_PROCESS_KEYRING),
        @intFromPtr(type_ptr),
        @intFromPtr(key_name),
        0,
    );
}

pub fn setPermission(key_id: i32, perm: u32) i32 {
    return keyctl(
        KEYCTL_SETPERM,
        @as(usize, @intCast(key_id)),
        @as(usize, perm),
        0,
        0,
    );
}

pub fn readKey(key_id: i32, buffer: ?[*]u8, len: usize) i32 {
    return keyctl(
        KEYCTL_READ,
        @as(usize, @intCast(key_id)),
        @intFromPtr(buffer),
        len,
        0,
    );
}

pub fn revokeKey(key_id: i32) i32 {
    return keyctl(
        KEYCTL_REVOKE,
        @as(usize, @intCast(key_id)),
        0,
        0,
        0,
    );
}
