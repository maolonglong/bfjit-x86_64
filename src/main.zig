const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const Allocator = std.mem.Allocator;

const Instruction = union(enum) {
    add: u8,
    move: i32,
    input,
    output,
    jump_right,
    jump_left,
};

fn getLastMutOrNull(instructions: std.ArrayList(Instruction)) ?*Instruction {
    if (instructions.items.len == 0) return null;
    return &instructions.items[instructions.items.len - 1];
}

fn parse(allocator: Allocator, source: []const u8) ![]Instruction {
    var instructions = std.ArrayList(Instruction).init(allocator);
    defer instructions.deinit();
    var bracket_stack = std.ArrayList(void).init(allocator);
    defer bracket_stack.deinit();

    for (source) |b| {
        const inst = switch (b) {
            '+', '-' => blk: {
                const v = if (b == '+') @as(u8, 1) else -%@as(u8, 1);
                if (getLastMutOrNull(instructions)) |last| {
                    if (last.* == .add) {
                        last.*.add +%= v;
                        continue;
                    }
                }
                break :blk Instruction{ .add = v };
            },
            '>', '<' => blk: {
                const v: i32 = if (b == '>') 1 else -1;
                if (getLastMutOrNull(instructions)) |last| {
                    if (last.* == .move) {
                        last.*.move += v;
                        continue;
                    }
                }
                break :blk Instruction{ .move = v };
            },
            '.' => Instruction{ .output = {} },
            ',' => Instruction{ .input = {} },
            '[' => blk: {
                bracket_stack.append({}) catch unreachable;
                break :blk Instruction{ .jump_right = {} };
            },
            ']' => blk: {
                if (bracket_stack.items.len == 0) return error.SyntaxError;
                bracket_stack.pop();
                break :blk Instruction{ .jump_left = {} };
            },
            else => continue,
        };
        try instructions.append(inst);
    }

    if (bracket_stack.items.len != 0) return error.SyntaxError;
    return instructions.toOwnedSlice();
}

fn compile(allocator: Allocator, instructions: []Instruction) ![]u8 {
    var code = std.ArrayList(u8).init(allocator);
    defer code.deinit();
    var jump_tbl = std.ArrayList(usize).init(allocator);
    defer jump_tbl.deinit();

    try code.appendSlice(&[_]u8{
        0x41, 0x55, // push %r13
        0x49, 0x89, 0xfd, // mov %rdi,%r13
        0x41, 0x54, // push %r12
        0x45, 0x31, 0xe4, // xor %r12d,%r12d
    });

    for (instructions) |inst| {
        switch (inst) {
            .add => |v| {
                try code.appendSlice(&[_]u8{
                    0x43, 0x80, 0x44, 0x25, 0x00, // addb ..., (%r13,%r12,1)
                });
                try code.append(v);
            },
            .move => |v| {
                if (v > 0) {
                    try code.appendSlice(&[_]u8{
                        0x49, 0x81, 0xc4, // add $...,%r12
                    });
                    try code.appendSlice(&std.mem.toBytes(v));
                } else if (v < 0) {
                    try code.appendSlice(&[_]u8{
                        0x49, 0x81, 0xec, // sub $...,%r12
                    });
                    try code.appendSlice(&std.mem.toBytes(-v));
                }
            },
            // write syscall
            .output => try code.appendSlice(&[_]u8{
                0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
                0xbf, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%edi
                0x4b, 0x8d, 0x74, 0x25, 0x00, // lea 0x0(%r13,%r12,1),%rsi
                0xba, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%edx
                0x0f, 0x05, // syscall
            }),
            // read syscall
            .input => try code.appendSlice(&[_]u8{
                0xb8, 0x00, 0x00, 0x00, 0x00, // mov $0x0,%eax
                0xbf, 0x00, 0x00, 0x00, 0x00, // mov $0x0,%edi
                0x4b, 0x8d, 0x74, 0x25, 0x00, // lea 0x0(%r13,%r12,1),%rsi
                0xba, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%edx
                0x0f, 0x05, // syscall
            }),
            .jump_right => {
                try code.appendSlice(&[_]u8{
                    0x43, 0x80, 0x7c, 0x25, 0x00, 0x00, // cmpb $0x0,0x0(%r13,%r12,1)
                    0x0f, 0x84, 0x00, 0x00, 0x00, 0x00, // je ...
                });
                try jump_tbl.append(code.items.len);
            },
            .jump_left => {
                const left = jump_tbl.pop();
                try code.appendSlice(&[_]u8{
                    0x43, 0x80, 0x7c, 0x25, 0x00, 0x00, // cmpb $0x0,0x0(%r13,%r12,1)
                    0x0f, 0x85, 0x00, 0x00, 0x00, 0x00, // jne ...
                });
                const right = code.items.len;
                const offset: i32 = @intCast(right - left);

                @memcpy(code.items[left - 4 .. left], &std.mem.toBytes(offset));
                @memcpy(code.items[right - 4 .. right], &std.mem.toBytes(-offset));
            },
        }
    }

    try code.appendSlice(&[_]u8{
        0x41, 0x5c, // pop %r12
        0x41, 0x5d, // pop %r13
        0xc3, // ret
    });

    return code.toOwnedSlice();
}

pub fn main() !void {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) {
        std.debug.print("Only x86_64-linux is supported.\n", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = os.argv;
    const unlimited = std.math.maxInt(usize);
    const source = switch (argv.len) {
        1 => blk: {
            const stdin = std.io.getStdIn();
            break :blk try stdin.reader().readAllAlloc(allocator, unlimited);
        },
        2 => blk: {
            const f = try std.fs.cwd().openFileZ(argv[1], .{});
            defer f.close();
            break :blk try f.reader().readAllAlloc(allocator, unlimited);
        },
        else => {
            std.debug.print("Usage: {s} [FILE]\n", .{argv[0]});
            os.exit(2);
        },
    };

    const optimized = try parse(allocator, source);
    allocator.free(source);

    const machine_code = try compile(allocator, optimized);
    allocator.free(optimized);
    const aligned_len = std.mem.alignForward(usize, machine_code.len, std.mem.page_size);

    const mem = try os.mmap(
        null,
        aligned_len,
        os.PROT.READ | os.PROT.WRITE,
        os.MAP.PRIVATE | os.MAP.ANONYMOUS,
        -1,
        0,
    );
    defer os.munmap(mem);

    @memcpy(mem[0..machine_code.len], machine_code);
    allocator.free(machine_code);

    try os.mprotect(mem, os.PROT.READ | os.PROT.EXEC);
    const bf_main: *const fn (memory: [*]u8) void = @ptrCast(mem[0..machine_code.len]);

    var memory = try allocator.alloc(u8, 0xffff);
    defer allocator.free(memory);
    @memset(memory, 0);
    bf_main(memory.ptr);
}
