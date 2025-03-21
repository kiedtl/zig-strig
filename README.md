# Strig

Compact string library for Zig.

- Each `Strig` is 24 bytes in size. 
- UTF-8 is required and enforced by the library.
- Strings up to 24 bytes can be inlined, using the same techniques used by
  Rust's `CompactString` crate.
- Longer strings are heap-allocated.
- The API is similar to an `ArrayListUnmanaged`; allocators are passed with each
  mutating call to save space.

Methods:

- `initLit`, `init`
- `deinit`
- `kind`, `capacity`, `len`, `isEmpty`
- `truncateTo`, `clear`
- `bytes`, `bytesMut`
- `eqToBytes`
- `ensureCapacity`
- `appendBytes`, `appendStrig`, `append`
- `insertBytes`, `insertStrig`, `insert`
- `removeChar`, `popChar`
- `isCharBoundary`
- `charAt`
- `findCharInd`
- `startsWith`, `endsWith`
- `makeUppercaseASCII`
- `makeLowercaseASCII`

Implements:

- Writer
- Format

## TODO

Strig is a work in progress. Comments, suggestions, PRs, useless bikeshedding,
and all Strig-related hatemail (`kiedtl at tilde dot team`) are appreciated.

- New APIs:
  - `findChar`, `findString`, `replaceChar`, `replaceString`, `retain`
  - `initFromBytesLossy`
  - `makeASCIILossy`
  - `repeat`
  - `shrinkTo`, `shrinkToFit`
  - `initRand` (generate random alphanumeric string?)
- API for existing functions may change to allow for better ergonomics.
- Fuzz-testing can be improved.
