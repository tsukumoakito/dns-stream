const std = @import("std");
const Io = std.Io;
const fs = std.fs;
const mem = std.mem;
const fmt = std.fmt;
const json = std.json;
const process = std.process;
const Dir = Io.Dir;
const Environ = process.Environ;
const Iterator = process.Args.Iterator;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const StaticStringMap = std.StaticStringMap;

const Store = @import("../data/Store.zig");
const root = @import("../root.zig");
const Format = @import("../view/Format.zig");

pub const LogMode = enum { auto, force, disable };

pub const AppConfig = struct {
    api_url: []const u8 = root.DEFAULT_API_URL,
    api_urls: [][]const u8 = &.{},
    log_path: []const u8 = root.DEFAULT_LOG_FILE,
    user: []const u8 = root.DEFAULT_USER,
    pass: ?[]const u8 = null,
    vault_path: ?[]const u8 = null,
    insecure: bool = false,
    log_mode: LogMode = .auto,
    drop_user: ?[]const u8 = null,
    time_offset: i64 = 0,
    polling_s: f64 = 1.0,
    api_limit: u16 = 500,
    user_agent: ?[]const u8 = null,
    no_color: bool = false,
    proxy: ?[]const u8 = null,
    scan_limit_mb: usize = 800,
    catchup_limit: usize = root.DEFAULT_API_MAX_CATCHUP,
    start_time: ?[]const u8 = null,
    end_time: ?[]const u8 = null,
    max_seen: usize = root.DEFAULT_MAX_SEEN,
};

fn isProxyDisabled(p: []const u8) bool {
    return p.len == 0 or mem.eql(u8, p, "none") or mem.eql(u8, p, "disable") or mem.eql(u8, p, "off");
}

fn mergeJsonConfig(io: Io, allocator: Allocator, path: []const u8, config: *AppConfig, environ: Environ) !void {
    _ = environ;
    const dir = Dir.cwd();
    const file = dir.openFile(io, path, .{ .mode = .read_only }) catch return;
    defer file.close(io);
    const stat_info = file.stat(io) catch return;
    const buf = allocator.alloc(u8, @intCast(stat_info.size)) catch return;
    defer allocator.free(buf);
    _ = file.readPositionalAll(io, buf, 0) catch return;
    var parsed = json.parseFromSlice(json.Value, allocator, buf, .{}) catch return;
    defer parsed.deinit();
    const root_obj = parsed.value.object;
    if (root_obj.get("api_url")) |v| {
        if (v == .string) {
            const dupe = allocator.dupe(u8, v.string) catch v.string;
            config.api_url = dupe;
            if (allocator.alloc([]const u8, 1)) |list| {
                list[0] = dupe;
                config.api_urls = list;
            } else |_| {
                config.api_urls = &.{};
            }
        } else if (v == .array) {
            var list: ArrayList([]const u8) = .empty;
            for (v.array.items) |item| {
                if (item == .string) {
                    const dupe = allocator.dupe(u8, item.string) catch continue;
                    list.append(allocator, dupe) catch continue;
                }
            }
            if (list.items.len > 0) {
                config.api_urls = list.toOwnedSlice(allocator) catch &.{};
                config.api_url = config.api_urls[0];
            }
        }
    }
    if (root_obj.get("log_path")) |v| if (v == .string) {
        config.log_path = allocator.dupe(u8, v.string) catch config.log_path;
    };
    if (root_obj.get("user")) |v| if (v == .string) {
        config.user = allocator.dupe(u8, v.string) catch config.user;
    };
    if (root_obj.get("pass")) |v| if (v == .string) {
        config.pass = allocator.dupe(u8, v.string) catch config.pass;
    };
    if (root_obj.get("vault_path")) |v| if (v == .string) {
        config.vault_path = allocator.dupe(u8, v.string) catch config.vault_path;
    };
    if (root_obj.get("insecure")) |v| if (v == .bool) {
        config.insecure = v.bool;
    };
    if (root_obj.get("drop_user")) |v| if (v == .string) {
        config.drop_user = allocator.dupe(u8, v.string) catch config.drop_user;
    };
    if (root_obj.get("start_time")) |v| if (v == .string) {
        config.start_time = allocator.dupe(u8, v.string) catch config.start_time;
    };
    if (root_obj.get("end_time")) |v| if (v == .string) {
        config.end_time = allocator.dupe(u8, v.string) catch config.end_time;
    };
    if (root_obj.get("user_agent")) |v| if (v == .string) {
        config.user_agent = allocator.dupe(u8, v.string) catch config.user_agent;
    };
    if (root_obj.get("log_mode")) |v| if (v == .string) {
        if (mem.eql(u8, v.string, "auto")) config.log_mode = .auto else if (mem.eql(u8, v.string, "force")) config.log_mode = .force else if (mem.eql(u8, v.string, "disable")) config.log_mode = .disable;
    };
    if (root_obj.get("polling_s")) |v| {
        config.polling_s = switch (v) {
            .float => v.float,
            .integer => @floatFromInt(v.integer),
            else => config.polling_s,
        };
    }
    if (root_obj.get("api_limit")) |v| if (v == .integer) {
        config.api_limit = @min(@as(u16, @intCast(v.integer)), root.API_MAX_LIMIT);
    };
    if (root_obj.get("no_color")) |v| if (v == .bool) {
        config.no_color = v.bool;
    };
    if (root_obj.get("scan_limit_mb")) |v| if (v == .integer) {
        config.scan_limit_mb = @as(usize, @intCast(v.integer));
    };
    if (root_obj.get("catchup_limit")) |v| if (v == .integer) {
        config.catchup_limit = @as(usize, @intCast(v.integer));
    };
    if (root_obj.get("time_offset")) |v| if (v == .integer) {
        config.time_offset = v.integer;
    };
    if (root_obj.get("max_seen")) |v| if (v == .integer) {
        config.max_seen = @as(usize, @intCast(v.integer));
    };
    if (root_obj.get("proxy")) |v| if (v == .string) {
        if (isProxyDisabled(v.string)) {
            config.proxy = "none";
        } else {
            config.proxy = allocator.dupe(u8, v.string) catch config.proxy;
        }
    };
    if (root_obj.get("ip")) |v| {
        if (v == .string) {
            if (Store.filter_ips_count < root.MAX_FILTERS) {
                const entry = &Store.filter_ips[Store.filter_ips_count];
                const safe_len = @min(v.string.len, entry.val.len);
                @memcpy(entry.val[0..safe_len], v.string[0..safe_len]);
                entry.len = @intCast(safe_len);
                Store.filter_ips_count += 1;
            }
        } else if (v == .array) {
            for (v.array.items) |item| {
                if (item == .string and Store.filter_ips_count < root.MAX_FILTERS) {
                    const entry = &Store.filter_ips[Store.filter_ips_count];
                    const safe_len = @min(item.string.len, entry.val.len);
                    @memcpy(entry.val[0..safe_len], item.string[0..safe_len]);
                    entry.len = @intCast(safe_len);
                    Store.filter_ips_count += 1;
                }
            }
        }
    }
    if (root_obj.get("name")) |v| {
        if (v == .string) {
            if (Store.filter_names_count < root.MAX_FILTERS) {
                const entry = &Store.filter_names[Store.filter_names_count];
                const safe_len = @min(v.string.len, entry.val.len);
                @memcpy(entry.val[0..safe_len], v.string[0..safe_len]);
                entry.len = @intCast(safe_len);
                Store.filter_names_count += 1;
            }
        } else if (v == .array) {
            for (v.array.items) |item| {
                if (item == .string and Store.filter_names_count < root.MAX_FILTERS) {
                    const entry = &Store.filter_names[Store.filter_names_count];
                    const safe_len = @min(item.string.len, entry.val.len);
                    @memcpy(entry.val[0..safe_len], item.string[0..safe_len]);
                    entry.len = @intCast(safe_len);
                    Store.filter_names_count += 1;
                }
            }
        }
    }
    if (root_obj.get("colors")) |colors_val| {
        if (colors_val == .object) {
            var iter = colors_val.object.iterator();
            while (iter.next()) |entry| {
                if (Store.ip_color_rules_count < root.MAX_COLOR_RULES) {
                    const pattern = entry.key_ptr.*;
                    const color_name = if (entry.value_ptr.* == .string) entry.value_ptr.*.string else continue;
                    var rule = &Store.ip_color_rules[Store.ip_color_rules_count];
                    const safe_len = @min(pattern.len, rule.pattern.len);
                    @memcpy(rule.pattern[0..safe_len], pattern[0..safe_len]);
                    rule.pattern_len = @intCast(safe_len);
                    rule.color_code = Format.getColorCode(color_name);
                    Store.ip_color_rules_count += 1;
                }
            }
        }
    }
}

pub fn load(io: Io, allocator: Allocator, it: *Iterator, environ: Environ) !AppConfig {
    var config = AppConfig{};
    var custom_config_path: ?[]const u8 = null;
    var args_list: ArrayList([]const u8) = .empty;
    defer args_list.deinit(allocator);

    _ = it.next();

    while (it.next()) |arg| {
        try args_list.append(allocator, arg);
        if (mem.eql(u8, arg, "--config")) {
            if (it.next()) |path| {
                custom_config_path = path;
                try args_list.append(allocator, path);
            }
        }
    }

    if (custom_config_path) |p| {
        try mergeJsonConfig(io, allocator, p, &config, environ);
    } else {
        try mergeJsonConfig(io, allocator, root.CONFIG_PATH_SYSTEM, &config, environ);
        if (environ.getPosix("HOME")) |home| {
            const p = try fs.path.join(allocator, &.{ home, root.CONFIG_PATH_USER });
            defer allocator.free(p);
            try mergeJsonConfig(io, allocator, p, &config, environ);
        }
    }

    if (environ.getPosix("AGH_URL")) |v| config.api_url = v;
    if (environ.getPosix("AGH_USER")) |v| config.user = v;
    if (environ.getPosix("AGH_PASS")) |v| config.pass = v;
    if (environ.getPosix("AGH_VAULT")) |v| config.vault_path = v;
    if (environ.getPosix("AGH_START")) |v| config.start_time = v;
    if (environ.getPosix("AGH_END")) |v| config.end_time = v;
    if (environ.getPosix("AGH_DROP_USER")) |v| config.drop_user = v;
    if (environ.getPosix("AGH_TIME_OFFSET")) |v| config.time_offset = fmt.parseInt(i64, v, 10) catch config.time_offset;
    if (environ.getPosix("AGH_MAX_SEEN")) |v| {
        if (v.len > 0) config.max_seen = fmt.parseInt(usize, v, 10) catch config.max_seen;
    }

    const Flag = enum {
        url,
        user,
        pass,
        vault,
        start,
        end,
        log_path,
        drop_user,
        proxy,
        polling,
        limit,
        scan_limit,
        catchup_limit,
        max_seen,
        time_offset,
        log_mode,
        insecure,
        no_color,
        ip,
        name,
        config,
    };

    const flag_map = StaticStringMap(Flag).initComptime(.{
        .{ "--url", .url },
        .{ "--user", .user },
        .{ "--pass", .pass },
        .{ "--vault", .vault },
        .{ "--start", .start },
        .{ "--end", .end },
        .{ "--log-path", .log_path },
        .{ "--drop-user", .drop_user },
        .{ "--proxy", .proxy },
        .{ "--polling", .polling },
        .{ "--limit", .limit },
        .{ "--scan-limit", .scan_limit },
        .{ "--catchup-limit", .catchup_limit },
        .{ "--max-seen", .max_seen },
        .{ "--time-offset", .time_offset },
        .{ "--log-mode", .log_mode },
        .{ "--insecure", .insecure },
        .{ "--no-color", .no_color },
        .{ "--ip", .ip },
        .{ "--name", .name },
        .{ "--config", .config },
    });

    var i: usize = 0;
    const args = args_list.items;
    while (i < args.len) {
        const arg = args[i];
        i += 1;
        const flag = flag_map.get(arg) orelse continue;
        switch (flag) {
            .url => {
                if (i < args.len) {
                    config.api_url = args[i];
                    if (allocator.alloc([]const u8, 1)) |list| {
                        list[0] = args[i];
                        config.api_urls = list;
                    } else |_| {}
                    i += 1;
                }
            },
            .user => {
                if (i < args.len) {
                    config.user = args[i];
                    i += 1;
                }
            },
            .pass => {
                if (i < args.len) {
                    config.pass = args[i];
                    i += 1;
                }
            },
            .vault => {
                if (i < args.len) {
                    config.vault_path = args[i];
                    i += 1;
                }
            },
            .start => {
                if (i < args.len) {
                    config.start_time = args[i];
                    i += 1;
                }
            },
            .end => {
                if (i < args.len) {
                    config.end_time = args[i];
                    i += 1;
                }
            },
            .log_path => {
                if (i < args.len) {
                    config.log_path = args[i];
                    i += 1;
                }
            },
            .drop_user => {
                if (i < args.len) {
                    config.drop_user = args[i];
                    i += 1;
                }
            },
            .proxy => {
                if (i < args.len) {
                    if (isProxyDisabled(args[i])) {
                        config.proxy = "none";
                    } else {
                        config.proxy = args[i];
                    }
                    i += 1;
                }
            },
            .polling => {
                if (i < args.len) {
                    config.polling_s = fmt.parseFloat(f64, args[i]) catch config.polling_s;
                    i += 1;
                }
            },
            .limit => {
                if (i < args.len) {
                    config.api_limit = fmt.parseInt(u16, args[i], 10) catch config.api_limit;
                    i += 1;
                }
            },
            .scan_limit => {
                if (i < args.len) {
                    config.scan_limit_mb = fmt.parseInt(usize, args[i], 10) catch config.scan_limit_mb;
                    i += 1;
                }
            },
            .catchup_limit => {
                if (i < args.len) {
                    config.catchup_limit = fmt.parseInt(usize, args[i], 10) catch config.catchup_limit;
                    i += 1;
                }
            },
            .max_seen => {
                if (i < args.len) {
                    config.max_seen = fmt.parseInt(usize, args[i], 10) catch config.max_seen;
                    i += 1;
                }
            },
            .time_offset => {
                if (i < args.len) {
                    config.time_offset = fmt.parseInt(i64, args[i], 10) catch config.time_offset;
                    i += 1;
                }
            },
            .log_mode => {
                if (i < args.len) {
                    if (mem.eql(u8, args[i], "auto")) config.log_mode = .auto else if (mem.eql(u8, args[i], "force")) config.log_mode = .force else if (mem.eql(u8, args[i], "disable")) config.log_mode = .disable;
                    i += 1;
                }
            },
            .insecure => config.insecure = true,
            .no_color => config.no_color = true,
            .ip => {
                while (i < args.len and !mem.startsWith(u8, args[i], "--")) {
                    if (Store.filter_ips_count < root.MAX_FILTERS) {
                        const entry = &Store.filter_ips[Store.filter_ips_count];
                        const val = args[i];
                        const safe_len = @min(val.len, entry.val.len);
                        @memcpy(entry.val[0..safe_len], val[0..safe_len]);
                        entry.len = @intCast(safe_len);
                        Store.filter_ips_count += 1;
                    }
                    i += 1;
                }
            },
            .name => {
                while (i < args.len and !mem.startsWith(u8, args[i], "--")) {
                    if (Store.filter_names_count < root.MAX_FILTERS) {
                        const entry = &Store.filter_names[Store.filter_names_count];
                        const val = args[i];
                        const safe_len = @min(val.len, entry.val.len);
                        @memcpy(entry.val[0..safe_len], val[0..safe_len]);
                        entry.len = @intCast(safe_len);
                        Store.filter_names_count += 1;
                    }
                    i += 1;
                }
            },
            .config => {
                i += 1;
            },
        }
    }
    return config;
}
