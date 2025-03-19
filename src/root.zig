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

    // CompactString crate uses values immediately after inline range to denote
    // heap-allocated strings, but by using values over here, we can better
    // detect some invalid states in fuzzing (since there are unused values "in
    // between").
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

    pub fn intoMut(self: PackedSlice) []u8 {
        return self.ptr.mut[0..self.len];
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

        pub fn entireThing(self: *Heap) []u8 {
            return self.data.ptr.mut[0..self.capacity];
        }

        pub fn entireThingConst(self: *const Heap) []const u8 {
            return self.data.ptr.mut[0..self.capacity];
        }
    };

    // NOTE: this function should copy the buffer before setting self, in case
    // bytes_ points to self's stack portion or similar.
    //
    // NOTE: length should be exactly bytes_.length
    //
    fn setHeap(self: *Self, bytes_: []const u8, p_capacity: ?usize, alloc: mem.Allocator) !void {
        const capacity = p_capacity orelse bytes_.len;
        assert(capacity >= bytes_.len);
        const buf = try alloc.alloc(u8, capacity);
        @memcpy(buf[0..bytes_.len], bytes_);
        self.heap = .{ .capacity = @intCast(capacity), .data = PackedSlice.from(buf) };
        self.heap.data.len = bytes_.len;
        self.magicPtr().* = Magic.HEAP;
        assert(self.len() == bytes_.len);
    }

    // Turn an immutable variant into either inlined or heap.
    fn setMutable(self: *Self, override_capacity: ?u64, alloc: mem.Allocator) !void {
        if (self.kind() != .immut)
            return;
        const c = if (override_capacity) |override| @max(override, self.len()) else self.len();
        if (c > 24)
            try self.setHeap(self.immut.into(), c, alloc)
        else
            self.* = try Self.from(self.bytes(), alloc);
    }

    // Create from a non-owned string. Buffer is not reused.
    //
    pub fn from(bytes_: []const u8, alloc: mem.Allocator) !Self {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;
        var b: Self = undefined;
        switch (bytes_.len) {
            0...23 => {
                @memcpy(b.getInlineData()[0..bytes_.len], bytes_);
                b.magicPtr().* = @as(u8, @intCast(bytes_.len)) + Magic.INLINE_SMALL;
            },
            24 => @memcpy(b.getInlineData()[0..bytes_.len], bytes_),
            else => try b.setHeap(bytes_, null, alloc),
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
            Magic.HEAP => alloc.free(self.heap.entireThingConst()),
            else => {},
        }
    }

    pub fn kind(self: *const Self) Kind {
        const I = Magic.INLINE_SMALL;
        return switch (self.magic()) {
            0...I - 1 => .{ .stack = 24 },
            I...I + 23 => |v| .{ .stack = @intCast(v - I) },
            I + 24...Magic.HEAP - 1 => unreachable,
            Magic.HEAP => .heap,
            Magic.IMMUT => .immut,
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

    // Will convert immutable strings to inlined/heap.
    pub fn bytesMut(self: *Self, alloc: mem.Allocator) ![]u8 {
        try self.setMutable(null, alloc);
        return switch (self.kind()) {
            .immut => unreachable,
            .stack => |l| self.getInlineData()[0..l],
            .heap => self.heap.data.intoMut(),
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

    // Ensure required MUTABLE capacity. In other words, constant strings will
    // be converted to inlined or heap strings.
    //
    pub fn ensureCapacity(self: *Self, needed_cap: u64, alloc: mem.Allocator) !void {
        switch (self.kind()) {
            .immut => try self.setMutable(needed_cap, alloc),
            .stack => |_| if (needed_cap > 24) try self.setHeap(self.bytes(), needed_cap, alloc),
            .heap => {
                const allocated_buffer = self.heap.entireThing();
                const data = self.heap.data.intoMut();

                if (self.heap.capacity < needed_cap) {
                    var new_capac = data.len;
                    while (new_capac < needed_cap)
                        new_capac = new_capac * 150 / 100;

                    if (alloc.remap(allocated_buffer, new_capac)) |newbuf| {
                        assert(newbuf.ptr == data.ptr);
                        self.heap.capacity = @intCast(newbuf.len);
                        self.heap.data.ptr = .{ .mut = newbuf.ptr };
                    } else {
                        const newbuf = try alloc.alloc(u8, new_capac);
                        defer alloc.free(allocated_buffer);
                        @memcpy(newbuf[0..data.len], data);
                        self.heap.data.ptr = .{ .mut = newbuf.ptr };
                        self.heap.capacity = @intCast(new_capac);
                    }
                }
            },
        }
    }

    fn appendBytesUnchecked(self: *Self, bytes_: []const u8, alloc: mem.Allocator) !void {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;

        const old_len = self.len();
        try self.ensureCapacity(old_len + bytes_.len, alloc);

        // Change length
        switch (self.kind()) {
            .immut => unreachable,
            .stack => |l| {
                const new_l = @as(u8, l) + bytes_.len;
                assert(new_l <= 24);
                if (new_l != 24)
                    self.magicPtr().* = Magic.INLINE_SMALL + @as(u8, @intCast(new_l));
            },
            .heap => self.heap.data.len += bytes_.len,
        }

        // Append
        const dest = switch (self.kind()) {
            .immut => unreachable,
            .stack => |_| self.getInlineData()[old_len .. old_len + bytes_.len],
            .heap => self.heap.data.ptr.mut[old_len .. old_len + bytes_.len],
        };
        @memcpy(dest, bytes_);
    }

    pub fn appendBytes(self: *Self, bytes_: []const u8, alloc: mem.Allocator) !void {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;
        try self.appendBytesUnchecked(bytes_, alloc);
    }

    pub fn appendStrig(self: *Self, strig: *const Self, alloc: mem.Allocator) !void {
        try self.appendBytesUnchecked(strig.bytes(), alloc);
    }

    pub fn append(self: *Self, codepoint: u21, alloc: mem.Allocator) !void {
        if (!unicode.utf8ValidCodepoint(codepoint))
            return error.InvalidUtf8;

        var buf: [4]u8 = undefined;
        const encoded_len = try std.unicode.utf8Encode(codepoint, buf[0..]);
        const slice = buf[0..encoded_len];

        try self.appendBytesUnchecked(slice, alloc);
    }

    // Modify the string in-place, converting ASCII characters to uppercase
    // variants.
    pub fn makeUppercaseASCII(self: *Self, alloc: mem.Allocator) !void {
        for (try self.bytesMut(alloc)) |*byte|
            switch (byte.*) {
                'a'...'z' => byte.* ^= ' ', // Retarded, yes, I know.
                else => {},
            };
    }

    // Modify the string in-place, converting ASCII characters to lowercase
    // variants.
    pub fn makeLowercaseASCII(self: *Self, alloc: mem.Allocator) !void {
        for (try self.bytesMut(alloc)) |*byte|
            switch (byte.*) {
                'A'...'Z' => byte.* ^= ' ', // Retarded, yes, I know.
                else => {},
            };
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

test "appendBytes" {
    var str = Strig.fromConst("Why, ") catch return;
    defer str.deinit(testing.allocator);

    try str.appendBytes("hello", testing.allocator);
    try testing.expectEqual(Strig.Kind{ .stack = 10 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "Why, hello"));

    try str.appendBytes(" there!", testing.allocator);
    try testing.expectEqual(Strig.Kind{ .stack = 17 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "Why, hello there!"));
}

test "append" {
    var str = Strig.fromConst("") catch return;
    defer str.deinit(testing.allocator);

    try testing.expectEqual(Strig.Kind.immut, str.kind());
    try testing.expectEqual(0, str.len());

    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('â', testing.allocator);

    try testing.expectEqual(Strig.Kind{ .stack = 4 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "aaâ"));

    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);

    try testing.expectEqual(Strig.Kind{ .stack = 8 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "aaâaaaa"));

    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);

    try testing.expectEqual(Strig.Kind{ .stack = 24 }, str.kind());

    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);
    try str.append('a', testing.allocator);

    try testing.expectEqual(Strig.Kind.heap, str.kind());
    try testing.expectEqual(28, str.len());
    try testing.expect(mem.eql(u8, str.bytes(), "aaâaaaaaaaaaaaaaaaaaaaaaaaa"));
}

test "makeLowercaseASCII, makeUppercaseASCII" {
    var str = Strig.fromConst("!@#ÂHello, this is a test. I SAID HELLO") catch unreachable;
    defer str.deinit(testing.allocator);

    try str.makeLowercaseASCII(testing.allocator);
    try testing.expect(mem.eql(u8, str.bytes(), "!@#Âhello, this is a test. i said hello"));

    try str.makeUppercaseASCII(testing.allocator);
    try testing.expect(mem.eql(u8, str.bytes(), "!@#ÂHELLO, THIS IS A TEST. I SAID HELLO"));
}

test "Basic roundtrip fuzz testing" {
    try testing.fuzz({}, struct {
        pub fn f(_: void, input: []const u8) anyerror!void {
            const str = Strig.from(input, testing.allocator) catch return;
            defer str.deinit(testing.allocator);
            try testing.expectEqual(str.len(), input.len);
            try testing.expect(mem.eql(u8, str.bytes(), input));
        }
    }.f, .{ .corpus = CORPUS });
}

test "Mutating via append()" {
    try testing.fuzz({}, struct {
        pub fn f(_: void, input: []const u8) anyerror!void {
            var str = Strig.fromConst("") catch return;
            defer str.deinit(testing.allocator);

            var buf = std.ArrayList(u8).init(testing.allocator);
            defer buf.deinit();

            var unicode_buf: [4]u8 = undefined;
            for (input) |codepoint| {
                const encoded_len = try std.unicode.utf8Encode(codepoint, unicode_buf[0..]);
                try buf.appendSlice(unicode_buf[0..encoded_len]);
                try str.append(codepoint, testing.allocator);
            }
            try testing.expectEqual(buf.items.len, str.len());
            try testing.expect(mem.eql(u8, str.bytes(), buf.items));
        }
    }.f, .{ .corpus = CORPUS });
}
