const std = @import("std");
const Io = std.Io;
const fmt = std.fmt;
const Dir = Io.Dir;
const File = Io.File;
const Terminal = Io.Terminal;

const Store = @import("../data/Store.zig");
const Config = @import("../logic/Config.zig");
const Format = @import("Format.zig");

pub fn print(
    terminal: *Terminal,
    io: Io,
    config: Config.AppConfig,
    final_url: []const u8,
    session_start_str: []const u8,
    effective_start_str: []const u8,
) !void {
    const stdout_file = File.stdout();

    try terminal.setColor(.bold);
    try stdout_file.writeStreamingAll(io, "🚀 DNS-Stream: Core Hybrid Relay Active\n");
    try terminal.setColor(.reset);

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "--- Confirmed Runtime Configuration ---\n");
    try terminal.setColor(.reset);

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "API Endpoint:      ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, final_url);
    try stdout_file.writeStreamingAll(io, "\n");

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "Local Log Path:    ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, config.log_path);
    try stdout_file.writeStreamingAll(io, "\n");

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "Auth User:         ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, config.user);
    try stdout_file.writeStreamingAll(io, "\n");

    const log_file_exists = blk: {
        const f = Dir.cwd().openFile(io, config.log_path, .{ .mode = .read_only }) catch {
            break :blk false;
        };
        f.close(io);
        break :blk true;
    };

    const mode_display = switch (config.log_mode) {
        .auto => if (log_file_exists) "Auto (File -> API)" else "Auto (API)",
        .force => "Force File Scan",
        .disable => "API Only",
    };
    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "Hybrid Log Mode:   ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, mode_display);
    try stdout_file.writeStreamingAll(io, "\n");

    var pol_buf: [32]u8 = undefined;
    const pol_str = try fmt.bufPrint(&pol_buf, "{d:.2}s", .{config.polling_s});
    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "Polling Interval:  ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, pol_str);
    try stdout_file.writeStreamingAll(io, "\n");

    var lim_buf: [64]u8 = undefined;
    const lim_str = try fmt.bufPrint(&lim_buf, "{d} entries (Catchup: {d})", .{ config.api_limit, config.catchup_limit });
    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "API Limits:        ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, lim_str);
    try stdout_file.writeStreamingAll(io, "\n");

    if (config.insecure) {
        try terminal.setColor(.bright_red);
        try stdout_file.writeStreamingAll(io, " ⚠️  TLS Verification: Disabled (Insecure Mode) ");
        try terminal.setColor(.reset);
        try stdout_file.writeStreamingAll(io, "\n");
    }

    if (Store.filter_ips_count > 0) {
        try terminal.setColor(.dim);
        try stdout_file.writeStreamingAll(io, "IP Filters:        ");
        try terminal.setColor(.cyan);
        for (Store.filter_ips[0..Store.filter_ips_count], 0..) |f, i| {
            if (i > 0) try stdout_file.writeStreamingAll(io, ", ");
            try stdout_file.writeStreamingAll(io, f.val[0..f.len]);
        }
        try terminal.setColor(.reset);
        try stdout_file.writeStreamingAll(io, "\n");
    }

    if (Store.filter_names_count > 0) {
        try terminal.setColor(.dim);
        try stdout_file.writeStreamingAll(io, "Name Filters:      ");
        try terminal.setColor(.cyan);
        for (Store.filter_names[0..Store.filter_names_count], 0..) |f, i| {
            if (i > 0) try stdout_file.writeStreamingAll(io, ", ");
            try stdout_file.writeStreamingAll(io, f.val[0..f.len]);
        }
        try terminal.setColor(.reset);
        try stdout_file.writeStreamingAll(io, "\n");
    }

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "---------------------------------------\n");
    try terminal.setColor(.reset);

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "Session Start (Local): ");
    try terminal.setColor(.reset);
    try stdout_file.writeStreamingAll(io, session_start_str);
    try stdout_file.writeStreamingAll(io, "\n");

    if (config.start_time != null) {
        try terminal.setColor(.dim);
        try stdout_file.writeStreamingAll(io, "Custom Start Point:    ");
        try terminal.setColor(.reset);
        try stdout_file.writeStreamingAll(io, effective_start_str);
        try stdout_file.writeStreamingAll(io, "\n");
    }
    if (config.end_time != null) {
        try terminal.setColor(.dim);
        try stdout_file.writeStreamingAll(io, "Custom End Point:      ");
        try terminal.setColor(.reset);
        try stdout_file.writeStreamingAll(io, Store.custom_end_ts[0..Store.custom_end_ts_len]);
        try stdout_file.writeStreamingAll(io, "\n");
    }

    try terminal.setColor(.dim);
    try stdout_file.writeStreamingAll(io, "Environment ID:        ");
    try terminal.setColor(.reset);
    const ua = config.user_agent orelse Store.user_agent[0..Store.user_agent_len];
    try stdout_file.writeStreamingAll(io, ua);
    try stdout_file.writeStreamingAll(io, "\n\n");
}
