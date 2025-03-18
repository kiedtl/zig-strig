// Note to self: never use usize here.

const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const unicode = std.unicode;
const testing = std.testing;

comptime {
    assert(@bitSizeOf(Strig) == 8 * 24);
}

pub const Magic = struct {
    pub const INLINE_SMALL = 192; // For inline strings 23 len or less
    pub const HEAP = 254;
    pub const IMMUT = 255;
};

pub const PackedSlice = packed struct {
    ptr: packed union { mut: [*]u8, immut: [*]const u8 },
    len: u64,

    pub fn from(d: []u8) PackedSlice {
        return .{ .ptr = .{ .mut = d.ptr }, .len = d.len };
    }

    pub fn fromConst(d: []const u8) PackedSlice {
        return .{ .ptr = .{ .immut = d.ptr }, .len = d.len };
    }

    pub fn into(self: PackedSlice) []const u8 {
        return self.ptr.immut[0..self.len];
    }
};

pub const Strig = packed union {
    immut: PackedSlice,
    stack: u192 align(1),
    heap: Heap align(1),

    pub const Self = @This();

    pub const Kind = union(enum) { immut, stack: u5, heap };

    pub const Heap = packed struct(u192) {
        data: PackedSlice,
        capacity: u56,
        end: u8 = undefined,
    };

    // Create from a non-owned string. Buffer is not reused.
    //
    pub fn from(bytes_: []const u8, alloc: mem.Allocator) !Self {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;
        var b: Self = undefined;
        switch (bytes_.len) {
            0...23 => {
                mem.copyForwards(u8, b.getInlineData(), bytes_);
                b.magicPtr().* = @as(u8, @intCast(bytes_.len)) + Magic.INLINE_SMALL;
            },
            24 => mem.copyForwards(u8, b.getInlineData(), bytes_),
            else => {
                const buf = try alloc.alloc(u8, bytes_.len);
                mem.copyForwards(u8, buf, bytes_);
                b.heap = .{ .capacity = @intCast(bytes_.len), .data = PackedSlice.from(buf) };
                b.magicPtr().* = Magic.HEAP;
            },
        }
        return b;
    }

    fn getInlineData(self: *Self) *[24]u8 {
        return @ptrCast(&self.stack);
    }

    fn getInlineDataConst(self: *const Self) *const [24]u8 {
        return @ptrCast(&self.stack);
    }

    fn magic(self: *const Self) u8 {
        return self.heap.end;
    }

    fn magicPtr(self: *Self) *u8 {
        return &self.heap.end;
    }

    pub fn fromConst(static_str: []const u8) !Self {
        if (!unicode.utf8ValidateSlice(static_str))
            return error.InvalidUtf8;
        var b: Self = .{ .immut = PackedSlice.fromConst(static_str) };
        b.magicPtr().* = Magic.IMMUT;
        return b;
    }

    pub fn deinit(self: *const Self, alloc: mem.Allocator) void {
        switch (self.magic()) {
            Magic.HEAP => alloc.free(self.heap.data.into()),
            else => {},
        }
    }

    pub fn kind(self: *const Self) Kind {
        const I = Magic.INLINE_SMALL;
        return switch (self.magic()) {
            0...I - 1 => .{ .stack = 24 },
            I...I + 23 => |v| .{ .stack = @intCast(v - I) },
            Magic.IMMUT => .immut,
            Magic.HEAP => .heap,
            else => unreachable,
        };
    }

    pub fn len(self: *const Self) u64 {
        return switch (self.kind()) {
            .immut => self.immut.len,
            .stack => |l| l,
            .heap => self.heap.data.len,
        };
    }

    pub fn bytes(self: *const Self) []const u8 {
        return switch (self.kind()) {
            .immut => self.immut.into(),
            .stack => |l| self.getInlineDataConst()[0..l],
            .heap => self.heap.data.into(),
        };
    }

    pub fn format(self: *const Self, comptime f: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (comptime mem.eql(u8, f, "s")) {
            @compileError("How about no");
        } else if (comptime !mem.eql(u8, f, "")) {
            @compileError("Unknown format string: '" ++ f ++ "'");
        }

        try writer.writeAll(self.bytes());
    }
};

const CORPUS: []const []const u8 = &.{
    @embedFile("fuzz/urandom-bdrVR"),
    @embedFile("fuzz/urandom-BP8AV"),
    @embedFile("fuzz/urandom-eHnQm"),
    @embedFile("fuzz/urandom-k8nVX"),
    @embedFile("fuzz/urandom-Lau1Z"),
    @embedFile("fuzz/urandom-o0QwN"),
    @embedFile("fuzz/urandom-RrKim"),
    @embedFile("fuzz/urandom-sSmU5"),
    @embedFile("fuzz/urandom-uSE1e"),
};

test "Created from a immutable string" {
    const mystring = try Strig.fromConst("Hello, world!");
    defer mystring.deinit(testing.allocator);
    try testing.expect(mem.eql(u8, mystring.bytes(), "Hello, world!"));
}

test "Basic roundtrip testing" {
    try testing.fuzz({}, struct {
        pub fn f(_: void, input: []const u8) anyerror!void {
            const str = Strig.from(input, testing.allocator) catch return;
            defer str.deinit(testing.allocator);
            try testing.expectEqual(str.len(), input.len);
            try testing.expect(mem.eql(u8, str.bytes(), input));
        }
    }.f, .{ .corpus = CORPUS });
}
