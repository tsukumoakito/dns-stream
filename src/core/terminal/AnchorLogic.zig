const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const fmt = std.fmt;
const http = std.http;
const debug = std.debug;
const Duration = Io.Duration;
const Client = http.Client;

const Store = @import("../../data/Store.zig");
const Engine = @import("../../logic/Engine.zig");
const Json = @import("../../logic/parser/Json.zig");

pub fn waitPrecision(io: Io, ms: u64) void {
    if (ms == 0) return;
    const d = Duration.fromMilliseconds(@intCast(ms));
    io.sleep(d, .awake) catch {};
}

pub fn handleAnchorLoss(
    io: Io,
    client: *Client,
    api_url: []const u8,
    api_limit: u16,
    catchup_limit: usize,
    query_url_buf: []u8,
    bridge: anytype,
) !void {
    const step = (@as(usize, api_limit) * 80) / 100;
    var probe_offset: usize = api_limit;
    const anchor_ts = Store.last_seen_ts[0..Store.last_seen_ts_len];
    var slide_offset: usize = 0;
    var anchor_lost = false;

    while (true) {
        while (probe_offset < catchup_limit) : (probe_offset += api_limit) {
            if (Store.should_exit) break;
            const probe_url = try fmt.bufPrint(query_url_buf, "{s}/querylog?limit=1&offset={d}", .{ api_url, probe_offset });
            const probe_data = Engine.fetchApiToBuffer(client, probe_url, "", Store.scratch_buffer) catch |err| {
                if (err == error.Unauthorized or err == error.ServiceUnavailable) break;
                break;
            };

            const oldest_ts = Json.getOldestTimestampInChunk(probe_data) orelse break;
            const ord = mem.order(u8, oldest_ts, anchor_ts);
            if (Store.debug_mode) debug.print("\x1b[90m[DEBUG]\x1b[0m Probing: Offset {d} -> Oldest {s} vs Anchor {s} -> {s}\n", .{ probe_offset, oldest_ts, anchor_ts, @tagName(ord) });

            if (ord != .gt) {
                const back_off = api_limit / 2;
                slide_offset = if (probe_offset > back_off) probe_offset - back_off else 0;
                break;
            }
            waitPrecision(io, 20);
        } else {
            if (Store.debug_mode) debug.print("\x1b[91m[DEBUG] ANCHOR LOST (Limit reached: {d})!\x1b[0m Resyncing to the oldest available records.\n", .{catchup_limit});
            slide_offset = if (probe_offset > api_limit) probe_offset - api_limit else 0;
            anchor_lost = true;
        }

        var drift_detected = false;
        while (slide_offset > 0) {
            if (Store.should_exit) break;
            const slide_url = try fmt.bufPrint(query_url_buf, "{s}/querylog?limit={d}&offset={d}", .{ api_url, api_limit, slide_offset });
            const slide_data = Engine.fetchApiToBuffer(client, slide_url, "", Store.scratch_buffer) catch |err| {
                if (err == error.Unauthorized or err == error.ServiceUnavailable) break;
                break;
            };

            const newest_in_chunk = Json.getNewestTimestampInChunk(slide_data) orelse "";
            const oldest_in_chunk = Json.getOldestTimestampInChunk(slide_data) orelse "";
            if (Store.debug_mode) debug.print("\x1b[90m[DEBUG]\x1b[0m Sliding: Offset {d}. Range [{s} to {s}] vs Anchor {s}\n", .{ slide_offset, oldest_in_chunk, newest_in_chunk, anchor_ts });

            if (!anchor_lost and slide_offset > 0 and oldest_in_chunk.len > 0 and mem.order(u8, oldest_in_chunk, anchor_ts) == .gt) {
                if (Store.debug_mode) debug.print("\x1b[91m[DEBUG] DRIFT DETECTED!\x1b[0m Re-diving from offset {d}\n", .{slide_offset});
                probe_offset = slide_offset;
                drift_detected = true;
                break;
            }

            bridge.processed_count = 0;
            bridge.force_mode = anchor_lost;
            bridge.total_in_chunk = mem.count(u8, slide_data, "\"time\":");
            bridge.chunk_cursor = 0;
            bridge.has_logged_accept = false;
            try Json.processJsonBulkReverse(slide_data, bridge.callback);

            if (Store.should_exit) break;

            if (slide_offset > step) slide_offset -= step else slide_offset = 0;
            waitPrecision(io, 50);
        }
        if (Store.should_exit or !drift_detected) break;
        waitPrecision(io, 100);
    }
}
