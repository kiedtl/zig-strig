const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const unicode = std.unicode;
const testing = std.testing;

comptime {
    assert(@bitSizeOf(Strig) == 8 * 24);
}

// Vector size and type for SIMD operations.
//
// FIXME: change this depending on architecture (I did some experiments, and
// found that larger Vectors tend to make indexOfByte somewhat slower than
// non-SIMD implementation)
//
const Vsz = 8;
const V = @Vector(Vsz, u8);

// Magic numbers at end of Strig type.
const Magic = struct {
    // The range [INLINE .. INLINE + 23] states that the string is
    //    a) inlined
    //    b) smaller than 23 bytes.
    pub const INLINE = 192;

    // Unused: 216-254.

    // Denotes a non-inlined, heap-allocated string.
    //
    // CompactString crate uses values immediately after inline range to denote
    // heap-allocated strings, but by using values over here, we can better
    // detect some invalid states in fuzzing (since there are invalid values "in
    // between").
    pub const HEAP = 255;
};

// Slices can't be in packed, curses. "No defined memory layout" my ass
//
const PackedSlice = packed struct {
    ptr: [*]u8,
    len: u64,

    pub fn from(d: []u8) PackedSlice {
        return .{ .ptr = d.ptr, .len = d.len };
    }

    pub fn into(self: PackedSlice) []u8 {
        return self.ptr[0..self.len];
    }
};

/// A UTF-8 string that *may* be inlined when smaller than 25 bytes.
///
pub const Strig = packed union {
    stack: u192,
    heap: Heap,

    /// The two invariants. <stack> denotes an inlined string of a size [0..24],
    /// heap denotes a heap-allocated string.
    pub const Kind = union(enum) { stack: u5, heap };

    /// Errors that can be returned by various functions.
    pub const Error = error{
        InvalidUtf8,
    } || mem.Allocator.Error || error{
        // FIXME: Cleanup UTF-8 handling, bundle unicode implementation since the
        // stdlib variations are being deprecated.
        //
        // Why isn't unicode.Utf8DecodeError public?
        Utf8ExpectedContinuation,
        Utf8OverlongEncoding,
        Utf8EncodesSurrogateHalf,
        Utf8CannotEncodeSurrogateHalf,
        CodepointTooLarge,
    };

    /// Heap-allocated variant of a Strig.
    ///
    /// - <data> is the packed slice returned by the allocator. It's length
    ///   is the used portion, not the entire capacity.
    /// - <capacity> is self-explanatory, defined as a 7-byte integer to leave
    ///   space for the magic value.
    /// - <end> is the magic value, present in both variants of Strig but
    ///   explicitly only defined here for convenience purposes.
    ///
    pub const Heap = packed struct(u192) {
        data: PackedSlice,
        capacity: u56,
        end: u8 = undefined,

        /// Return the entire slice with the entire capacity.
        pub fn entireThing(self: *Heap) []u8 {
            return self.data.ptr[0..self.capacity];
        }

        /// Return the entire const slice with the entire capacity.
        pub fn entireThingConst(self: *const Heap) []const u8 {
            return self.data.ptr[0..self.capacity];
        }
    };

    const Self = @This();

    pub const empty: Self = .{
        .stack = @as(u192, @bitCast(([1]u8{0xAA} ** 23) ++ [1]u8{Magic.INLINE})),
    };

    // NOTE: this function should copy the buffer before setting self, in case
    // bytes_ points to self's stack portion or similar.
    //
    // NOTE: length should be exactly bytes_.length
    //
    fn setHeap(self: *Self, bytes_: []const u8, p_capacity: ?usize, alloc: mem.Allocator) !void {
        assert(self.kind() != .heap);
        const capac = p_capacity orelse bytes_.len;
        assert(capac >= bytes_.len);
        const buf = try alloc.alloc(u8, capac);
        @memcpy(buf[0..bytes_.len], bytes_);
        self.heap = .{ .capacity = @intCast(capac), .data = PackedSlice.from(buf) };
        self.heap.data.len = bytes_.len;
        self.magicPtr().* = Magic.HEAP;
        assert(self.len() == bytes_.len);
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

    /// Initializes a new comptime-known string. It is a compile error if it
    /// cannot be inlined or if it's invalid UTF-8.
    ///
    /// Does not allocate. Should go without saying.
    ///
    pub fn initLit(comptime bytes_: []const u8) Self {
        if (bytes_.len > 24)
            @compileError("Cannot inline string greater than 24 bytes.");
        if (!comptime unicode.utf8ValidateSlice(bytes_))
            @compileError("String is not valid UTF-8.");

        var b: Self = undefined;
        @memcpy(b.getInlineData()[0..bytes_.len], bytes_);
        if (bytes_.len != 24)
            b.magicPtr().* = @as(u8, @intCast(bytes_.len)) + Magic.INLINE;
        return b;
    }

    /// Create from a non-owned buffer.
    ///
    /// The buffer is not reused. Allocations will occur as necessary.
    pub fn init(bytes_: []const u8, alloc: mem.Allocator) !Self {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;
        var b: Self = undefined;
        switch (bytes_.len) {
            0...24 => {
                @memcpy(b.getInlineData()[0..bytes_.len], bytes_);
                if (bytes_.len != 24)
                    b.magicPtr().* = @as(u8, @intCast(bytes_.len)) + Magic.INLINE;
            },
            else => try b.setHeap(bytes_, null, alloc),
        }
        return b;
    }

    /// Free any allocations. If inlined, does nothing.
    pub fn deinit(self: *const Self, alloc: mem.Allocator) void {
        switch (self.magic()) {
            Magic.HEAP => alloc.free(self.heap.entireThingConst()),
            else => {},
        }
    }

    /// Clone the Strig into an identical copy, allocating as necessary.
    pub fn clone(self: *const Self, alloc: mem.Allocator) !Strig {
        return switch (self.magic()) {
            Magic.HEAP => {
                var b: Self = undefined;
                try b.setHeap(self.heap.entireThingConst(), null, alloc);
                return b;
            },
            else => return self.*, // No need to allocate.
        };
    }

    /// Return a value determining whether the string is inlined or not (and if
    /// so, its length).
    ///
    pub fn kind(self: *const Self) Kind {
        const I = Magic.INLINE;
        return switch (self.magic()) {
            0...I - 1 => .{ .stack = 24 },
            I...I + 23 => |v| .{ .stack = @intCast(v - I) },
            I + 24...Magic.HEAP - 1 => unreachable,
            Magic.HEAP => .heap,
        };
    }

    /// Return the capacity of the string. If inlined, the capacity is always
    /// 24.
    pub fn capacity(self: *const Self) u56 {
        return switch (self.kind()) {
            .stack => |_| 24,
            .heap => self.heap.capacity,
        };
    }

    /// Return the number of BYTES in the string.
    pub fn len(self: *const Self) u64 {
        return switch (self.kind()) {
            .stack => |l| l,
            .heap => self.heap.data.len,
        };
    }

    /// Determine if the string contains no elements.
    pub fn isEmpty(self: *const Self) void {
        return self.len() == 0;
    }

    /// Sets the length to a smaller amount. Asserts that <to> is indeed equal
    /// to or smaller than the current length. Does not free capacity.
    ///
    pub fn truncateTo(self: *Self, to: usize) void {
        assert(self.len() >= to);
        defer assert(self.len() == to);
        return switch (self.kind()) {
            .stack => |_| self.magicPtr().* = Magic.INLINE + @as(u8, @intCast(to)),
            .heap => self.heap.data.len = to,
        };
    }

    /// Truncate the string to zero. Does not free capacity.
    pub fn clear(self: *Self) void {
        self.truncateTo(0);
    }

    /// Do a naive, non-Unicode-aware byte-to-byte comparison.
    pub fn eqToBytes(self: *const Self, bytes_: []const u8) bool {
        return mem.eql(u8, self.bytes(), bytes_);
    }

    /// Return a slice of the string's bytes.
    pub fn bytes(self: *const Self) []const u8 {
        return switch (self.kind()) {
            .stack => |l| self.getInlineDataConst()[0..l],
            .heap => self.heap.data.into(),
        };
    }

    /// Return a slice of the string's bytes.
    pub fn bytesMut(self: *Self) []u8 {
        return switch (self.kind()) {
            .stack => |l| self.getInlineData()[0..l],
            .heap => self.heap.data.into(),
        };
    }

    /// Format a string, printing out its raw bytes.
    ///
    /// Format specifier should be empty.
    pub fn format(self: *const Self, comptime f: []const u8, _: std.fmt.FormatOptions, w: anytype) !void {
        if (comptime mem.eql(u8, f, "s")) {
            @compileError("How about no");
        } else if (comptime !mem.eql(u8, f, "")) {
            @compileError("Unknown format string: '" ++ f ++ "'");
        }

        try w.writeAll(self.bytes());
    }

    /// Ensure the required capacity exists. Inlined strings will be converted
    /// to heap-allocated as necessary.
    pub fn ensureCapacity(self: *Self, needed_cap: u64, alloc: mem.Allocator) !void {
        switch (self.kind()) {
            .stack => |_| if (needed_cap > 24) try self.setHeap(self.bytes(), needed_cap, alloc),
            .heap => {
                const allocated_buffer = self.heap.entireThing();
                const data = self.heap.data.into();

                if (self.heap.capacity < needed_cap) {
                    var new_capac = data.len;
                    while (new_capac < needed_cap)
                        new_capac = new_capac * 150 / 100;

                    if (alloc.remap(allocated_buffer, new_capac)) |newbuf| {
                        self.heap.capacity = @intCast(newbuf.len);
                        self.heap.data.ptr = newbuf.ptr;
                    } else {
                        const newbuf = try alloc.alloc(u8, new_capac);
                        defer alloc.free(allocated_buffer);
                        @memcpy(newbuf[0..data.len], data);
                        self.heap.data.ptr = newbuf.ptr;
                        self.heap.capacity = @intCast(new_capac);
                    }
                }
            },
        }
    }

    // <at> is the index into the string's raw data, not a character index.
    // Doesn't check that the string is uncorrupt, that bytes is valid UTF-8,
    // that inserting wouldn't split codepoints, etc.
    //
    fn insertBytesUnchecked(self: *Self, bytes_: []const u8, at: usize, alloc: mem.Allocator) Error!void {
        assert(at <= self.len());

        const old_len = self.len();
        try self.ensureCapacity(old_len + bytes_.len, alloc);
        const buffer = switch (self.kind()) {
            .stack => self.getInlineData(),
            .heap => self.heap.entireThing(),
        };

        // Shift old data over
        mem.copyBackwards(u8, buffer[at + bytes_.len .. old_len + bytes_.len], buffer[at..old_len]);

        // Insert new buffer
        @memcpy(buffer[at .. at + bytes_.len], bytes_);

        // Change length
        switch (self.kind()) {
            .stack => |_| {
                const new_l = old_len + bytes_.len;
                assert(new_l <= 24);
                if (new_l != 24)
                    self.magicPtr().* = Magic.INLINE + @as(u8, @intCast(new_l));
            },
            .heap => self.heap.data.len += bytes_.len,
        }
    }

    /// Append bytes to the string. An error is returned if the bytes aren't
    /// valid UTF-8.
    pub fn appendBytes(self: *Self, bytes_: []const u8, alloc: mem.Allocator) Error!void {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;
        try self.insertBytesUnchecked(bytes_, self.len(), alloc);
    }

    /// Append another Strig to this Strig.
    pub fn appendStrig(self: *Self, strig: *const Self, alloc: mem.Allocator) Error!void {
        try self.insertBytesUnchecked(strig.bytes(), self.len(), alloc);
    }

    /// Append a codepoint to this Strig. Returns an error if the codepoint
    /// isn't valid.
    pub fn append(self: *Self, codepoint: u21, alloc: mem.Allocator) Error!void {
        if (!unicode.utf8ValidCodepoint(codepoint))
            return error.InvalidUtf8;

        var buf: [4]u8 = undefined;
        const encoded_len = try std.unicode.utf8Encode(codepoint, buf[0..]);
        const slice = buf[0..encoded_len];

        try self.insertBytesUnchecked(slice, self.len(), alloc);
    }

    pub const WriterCtx = struct {
        str: *Self,
        alloc: mem.Allocator,

        pub fn appendWrite(self: WriterCtx, m: []const u8) Error!usize {
            try self.str.appendBytes(m, self.alloc);
            return m.len;
        }
    };
    pub const Writer = std.io.Writer(WriterCtx, Error, WriterCtx.appendWrite);

    /// Returns a Writer for this Strig.
    pub fn writer(self: *Self, alloc: mem.Allocator) Writer {
        return .{ .context = .{ .str = self, .alloc = alloc } };
    }

    /// Inserts bytes into the specific index.
    ///
    /// Returns an error if the bytes aren't valid UTF-8, or if insertion would
    /// split a UTF-8 character sequence.
    pub fn insertBytes(self: *Self, bytes_: []const u8, at: usize, alloc: mem.Allocator) !void {
        if (!unicode.utf8ValidateSlice(bytes_))
            return error.InvalidUtf8;
        if (!self.isCharBoundary(at))
            return error.WouldRuinString;
        try self.insertBytesUnchecked(bytes_, at, alloc);
    }

    /// Inserts bytes into the specific index.
    ///
    /// an error if insertion would split a UTF-8 character sequence.
    pub fn insertStrig(self: *Self, strig: *const Self, at: usize, alloc: mem.Allocator) !void {
        if (!self.isCharBoundary(at))
            return error.WouldRuinString;
        try self.insertBytesUnchecked(strig.bytes(), at, alloc);
    }

    /// Inserts bytes into the specific index.
    ///
    /// Returns an error if the codepoint isn't valid, or if insertion would
    /// split a UTF-8 character sequence.
    pub fn insert(self: *Self, codepoint: u21, at: usize, alloc: mem.Allocator) !void {
        if (!unicode.utf8ValidCodepoint(codepoint))
            return error.InvalidUtf8;
        if (!self.isCharBoundary(at))
            return error.WouldRuinString;

        var buf: [4]u8 = undefined;
        const encoded_len = try std.unicode.utf8Encode(codepoint, buf[0..]);
        const slice = buf[0..encoded_len];

        try self.insertBytesUnchecked(slice, at, alloc);
    }

    fn removeRangeUnchecked(self: *Self, at: usize, n: usize) void {
        const data = self.bytesMut();
        if (at != data.len - 1)
            mem.copyForwards(u8, data[at .. data.len - n], data[at + n ..]);
        self.truncateTo(data.len - n);
    }

    /// Remove a character sequence from the given index.
    ///
    /// Panics if index isn't at a character boundary.
    pub fn removeChar(self: *Self, at: usize) !u21 {
        assert(at < self.len());
        if (!self.isCharBoundary(at))
            return error.WouldRuinString;

        const data = self.bytesMut();
        const seqlen = unicode.utf8ByteSequenceLength(data[at]) catch unreachable;
        const codepoint = unicode.utf8Decode(data[at .. at + seqlen]) catch unreachable;
        self.removeRangeUnchecked(at, seqlen);
        return codepoint;
    }

    /// Pops a character off the end and returns it.
    pub fn popChar(self: *Self) ?u21 {
        const data = self.bytes();
        if (data.len == 0)
            return null;

        // Find the end of the UTF-8 sequence, by moving backwards until we
        // find the first non-continuation byte.
        var start = data.len - 1;
        var seqlen: usize = 1;
        while (data[start] & 0b11000000 == 0b10000000) : (seqlen += 1) {
            if (start == 0)
                // Broken sequence at beginning of string.
                @panic("String contains corrupted data.");
            start -= 1;
        }

        const codepoint = unicode.utf8Decode(data[start .. start + seqlen]) catch unreachable;
        self.removeRangeUnchecked(start, seqlen);
        return codepoint;
    }

    /// Checks if a given index is at a the BEGINNING of a UTF-8 character
    /// sequence.
    pub fn isCharBoundary(self: *const Self, at: usize) bool {
        return self.bytes()[at] & 0b11000000 != 0b10000000;
    }

    /// Find the index of a specific byte in the string.
    ///
    pub fn indexOfByte(self: *const Self, scalar: u8) ?usize {
        const buf = self.bytes();
        const splat: V = @splat(scalar);

        // SIMD
        var i: usize = 0;
        while (i + Vsz < buf.len) : (i += Vsz) {
            const chunk: V = @as(*const [Vsz]u8, @ptrCast(buf.ptr[i..]))[0..Vsz].*;
            if (@reduce(.Or, chunk == splat))
                // Find exact index
                for (0..Vsz) |j|
                    if (chunk[j] == scalar)
                        return i + j;
        }

        // Naive fallback
        // FIXME: test that there's no overlap between SIMD search and naive one
        if (i != buf.len)
            for (buf[i..], i..) |ch, j|
                if (ch == scalar)
                    return j;

        return null;
    }

    /// Returns the Unicode codepoint at the given index.
    ///
    /// Returns an error if the index isn't at a character boundary.
    pub fn charAt(self: *const Self, ind: usize) !u21 {
        if (!self.isCharBoundary(ind))
            return error.NotCharBoundary;
        const data = self.bytes();
        const seqlen = try unicode.utf8ByteSequenceLength(data[ind]);
        return unicode.utf8Decode(data[ind .. ind + seqlen]) catch unreachable;
    }

    /// Gets the index of the nth (starting from 0) Unicode codepoint.
    ///
    /// For example, findCharInd("yeß?", 3) should return 4, since 'ß' is
    /// encoded as 2 bytes.
    ///
    /// Returns an error in case of an out of bounds.
    pub fn findCharInd(self: *const Self, nth: usize) !u56 {
        const l = self.len();
        const data = self.bytes();

        var ch_ctr: u56, var i: u56 = .{ 0, 0 };
        while (ch_ctr < nth) : (ch_ctr += 1) {
            if (i >= l) return error.OutOfBounds;
            i += try unicode.utf8ByteSequenceLength(data[i]);
        }

        return i;
    }

    /// Naive mem.startsWith wrapper.
    pub fn startsWith(self: *const Self, bites: []const u8) bool {
        // Don't bother checking UTF-8 compliancy
        return mem.startsWith(u8, self.bytes(), bites);
    }

    /// Naive mem.endsWith wrapper.
    pub fn endsWith(self: *const Self, bites: []const u8) bool {
        // Don't bother checking UTF-8 compliancy
        return mem.startsWith(u8, self.bytes(), bites);
    }

    /// Modify the string in-place, converting ASCII characters to uppercase
    /// variants.
    pub fn makeUppercaseASCII(self: *Self) !void {
        for (self.bytesMut()) |*byte|
            switch (byte.*) {
                'a'...'z' => byte.* ^= ' ', // Retarded, yes, I know.
                else => {},
            };
    }

    /// Modify the string in-place, converting ASCII characters to lowercase
    /// variants.
    pub fn makeLowercaseASCII(self: *Self) !void {
        for (self.bytesMut()) |*byte|
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

    @embedFile("fuzz/rand-tm41o"),
    @embedFile("fuzz/rand-sm8i9"),
};

test "empty" {
    var str = Strig.empty;
    try testing.expectEqual(Strig.Kind{ .stack = 0 }, str.kind());
}

test "insertBytes" {
    var str = try Strig.init("First name: <>; Last name: <>", testing.allocator);
    defer str.deinit(testing.allocator);

    try str.insertBytes("Fëanor", 13, testing.allocator);
    try str.insertBytes("Curufinwë", 35, testing.allocator);

    try testing.expect(mem.eql(u8, str.bytes(), "First name: <Fëanor>; Last name: <Curufinwë>"));
}

test "appendBytes" {
    var str = Strig.initLit("Why, ");
    defer str.deinit(testing.allocator);

    try str.appendBytes("hello", testing.allocator);
    try testing.expectEqual(Strig.Kind{ .stack = 10 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "Why, hello"));

    try str.appendBytes(" there!", testing.allocator);
    try testing.expectEqual(Strig.Kind{ .stack = 17 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "Why, hello there!"));
}

test "append" {
    var str = Strig.empty;
    defer str.deinit(testing.allocator);

    try testing.expectEqual(Strig.Kind{ .stack = 0 }, str.kind());
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

test "writer" {
    var str = Strig.initLit("Why, ");
    defer str.deinit(testing.allocator);
    const writer = str.writer(testing.allocator);

    try writer.writeAll("hello");
    try testing.expectEqual(Strig.Kind{ .stack = 10 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "Why, hello"));

    try writer.print(" {s}!", .{"Zig User"});
    try testing.expectEqual(Strig.Kind{ .stack = 20 }, str.kind());
    try testing.expect(mem.eql(u8, str.bytes(), "Why, hello Zig User!"));
}

test "makeLowercaseASCII, makeUppercaseASCII" {
    var str = Strig.init("!@#ÂHello, this is a test. I SAID HELLO", testing.allocator) catch unreachable;
    defer str.deinit(testing.allocator);

    try str.makeLowercaseASCII();
    try testing.expect(mem.eql(u8, str.bytes(), "!@#Âhello, this is a test. i said hello"));

    try str.makeUppercaseASCII();
    try testing.expect(mem.eql(u8, str.bytes(), "!@#ÂHELLO, THIS IS A TEST. I SAID HELLO"));
}

test "removeChar" {
    var str = Strig.initLit("Thïs is â teßt");
    defer str.deinit(testing.allocator);

    try testing.expectEqual('T', try str.removeChar(0));
    try testing.expectEqual('ï', try str.removeChar(1));
    try testing.expect(mem.eql(u8, str.bytes(), "hs is â teßt"));

    try testing.expectEqual('ß', try str.removeChar(12));
    try testing.expect(mem.eql(u8, str.bytes(), "hs is â tet"));
}

test "popChar" {
    var str = Strig.init("Grâß—fëð șôųŕđøūǵḣ", testing.allocator) catch unreachable;
    defer str.deinit(testing.allocator);

    const chars = [_]u21{
        'G',  'r',  'â', 'ß', '—', 'f',  'ë', 'ð', ' ',
        'ș', 'ô', 'ų', 'ŕ', 'đ',  'ø', 'ū', 'ǵ', 'ḣ',
    };

    for (0..chars.len) |ind|
        try testing.expectEqual(chars[chars.len - ind - 1], str.popChar().?);

    try testing.expectEqual(null, str.popChar());
}

test "indexOfByte" {
    const str = Strig.initLit("This is a test.");
    defer str.deinit(testing.allocator);

    try testing.expectEqual(null, str.indexOfByte('z'));
    try testing.expectEqual(2, str.indexOfByte('i'));
    try testing.expectEqual(0, str.indexOfByte('T'));
    try testing.expectEqual(4, str.indexOfByte(' '));
}

test "findCharInd" {
    var str = Strig.init("He hástenëd → Alqualonde", testing.allocator) catch unreachable;
    defer str.deinit(testing.allocator);

    try testing.expectEqual(0, try str.findCharInd(0));
    try testing.expectEqual(6, try str.findCharInd(5));
    try testing.expectEqual(14, try str.findCharInd(12));
    try testing.expectError(error.OutOfBounds, str.findCharInd(999));
}

test "charAt" {
    var str = Strig.init("and ßpøkë to thē Teleri", testing.allocator) catch unreachable;
    defer str.deinit(testing.allocator);

    try testing.expectEqual('ß', try str.charAt(4));
    try testing.expectEqual('ø', try str.charAt(7));
    try testing.expectEqual('e', try str.charAt(24));
}

test "Fuzz: basic roundtrip testing" {
    try testing.fuzz({}, struct {
        pub fn f(_: void, input: []const u8) anyerror!void {
            const str = Strig.init(input, testing.allocator) catch return;
            defer str.deinit(testing.allocator);
            try testing.expectEqual(str.len(), input.len);
            try testing.expect(mem.eql(u8, str.bytes(), input));
        }
    }.f, .{ .corpus = CORPUS });
}

test "Fuzz: mutating via append()" {
    try testing.fuzz({}, struct {
        pub fn f(_: void, input: []const u8) anyerror!void {
            var str = Strig.init("", testing.allocator) catch return;
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

test "Fuzz: random actions" {
    const Ctx = struct {
        rng: std.Random,
        con: *std.ArrayList(u8),
        str: *Strig,
        alloc: mem.Allocator,
    };

    var gpa = std.heap.DebugAllocator(.{}){};
    var rng = std.Random.DefaultPrng.init(0xdeadbeef);
    var con = std.ArrayList(u8).init(gpa.allocator());
    var str = Strig.empty;
    var cty = Ctx{
        .rng = rng.random(),
        .con = &con,
        .str = &str,
        .alloc = gpa.allocator(),
    };

    defer _ = gpa.deinit();
    defer con.deinit();
    defer str.deinit(gpa.allocator());

    try testing.fuzz(&cty, struct {
        pub fn f(ctx: *Ctx, input: []const u8) anyerror!void {
            if (ctx.str.len() == 0) {
                ctx.str.appendBytes(input, ctx.alloc) catch return;
                ctx.con.appendSlice(input) catch unreachable;
                return;
            }

            const Action = union(enum) {
                AppendBytes,
                InsertBytes,
                RemoveChar,
                PopChar,
            };
            const ACTIONS = &[_]Action{
                .AppendBytes, .InsertBytes,
                .RemoveChar,  .PopChar,
            };

            const action = ACTIONS[ctx.rng.int(usize) % ACTIONS.len];
            const randpos = ctx.rng.int(usize) % ctx.str.len();
            switch (action) {
                .AppendBytes => {
                    ctx.str.appendBytes(input, ctx.alloc) catch return;
                    ctx.con.appendSlice(input) catch unreachable;
                },
                .InsertBytes => {
                    ctx.str.insertBytes(input, randpos, ctx.alloc) catch return;
                    ctx.con.insertSlice(randpos, input) catch unreachable;
                },
                .RemoveChar => {
                    const codepoint = ctx.str.removeChar(randpos) catch return;
                    const l = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
                    for (0..l) |_|
                        _ = ctx.con.orderedRemove(randpos);
                },
                .PopChar => {
                    const codepoint = ctx.str.popChar().?;
                    const l = std.unicode.utf8CodepointSequenceLength(codepoint) catch unreachable;
                    for (0..l) |_|
                        _ = ctx.con.pop().?;
                },
            }

            try testing.expectEqual(ctx.con.items.len, ctx.str.len());
            try testing.expect(mem.eql(u8, ctx.str.bytes(), ctx.con.items));
        }
    }.f, .{ .corpus = CORPUS });
}
