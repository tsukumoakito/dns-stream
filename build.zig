const std = @import("std");

pub fn build(b: *std.Build) void {
    const zon_info = @import("build.zig.zon");
    const version = comptime std.SemanticVersion.parse(zon_info.version) catch unreachable;

    const release_date_unix = zon_info.release_date_unix;
    const version_str = b.fmt("{d}.{d}.{d}", .{ version.major, version.minor, version.patch });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", version_str);

    const mod = b.addModule("dns_stream", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .link_libc = true,
    });

    mod.linkSystemLibrary("gcrypt", .{});
    mod.linkSystemLibrary("gpgme", .{});
    mod.linkSystemLibrary("gpg-error", .{});

    const exe = b.addExecutable(.{
        .name = "dns-stream",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "dns_stream", .module = mod },
                .{ .name = "build_options", .module = options.createModule() },
            },
        }),
    });

    b.installArtifact(exe);

    const is_windows_host = b.graph.host.result.os.tag == .windows;
    const scdoc_prog = if (is_windows_host) null else b.findProgram(&.{"scdoc"}, &.{}) catch null;

    if (scdoc_prog) |prog_path| {
        const man_step = b.step("man", "Generate and install man pages");

        const man_files = [_][2][]const u8{
            .{ "doc/dns-stream.1.scd", "dns-stream.1" },
            .{ "doc/dns-stream.ja.1.scd", "dns-stream.ja.1" },
        };

        for (man_files) |f| {
            const src = f[0];
            const out_name = f[1];

            const scdoc = b.addSystemCommand(&.{prog_path});
            scdoc.setEnvironmentVariable("SOURCE_DATE_EPOCH", release_date_unix);
            scdoc.setStdIn(.{ .lazy_path = b.path(src) });
            const man_out = scdoc.captureStdOut(.{ .basename = out_name });

            const dest_path = if (std.mem.indexOf(u8, src, ".ja.") != null) "share/man/ja/man1/dns-stream.1" else "share/man/man1/dns-stream.1";
            man_step.dependOn(&b.addInstallFile(man_out, dest_path).step);
        }
        b.getInstallStep().dependOn(man_step);
    } else if (!is_windows_host) {
        std.debug.print("Warning: 'scdoc' not found in PATH. Man pages will not be generated.\n", .{});
    }

    const install_manual_en = b.addInstallFile(b.path("doc/MANUAL.md"), "doc/MANUAL.md");
    const install_manual_ja = b.addInstallFile(b.path("doc/MANUAL_ja.md"), "doc/MANUAL_ja.md");

    b.getInstallStep().dependOn(&install_manual_en.step);
    b.getInstallStep().dependOn(&install_manual_ja.step);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
        .use_llvm = true,
        .use_lld = true,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
        .use_llvm = true,
        .use_lld = true,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
