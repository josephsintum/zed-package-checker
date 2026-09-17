//! Turning byte offsets into editor positions.
//!
//! Parsers report byte offsets; LSP wants zero-based line and column, with the
//! column in whatever unit the client negotiated. Carriage returns need no
//! handling: a `\r` sits at the end of a line, after everything anything here
//! ever points at.

use crate::model::{Position, Range};

/// Line start offsets, for converting a byte offset to a position.
pub struct LineIndex {
    starts: Vec<u32>,
}

impl LineIndex {
    pub fn new(src: &str) -> LineIndex {
        let mut starts = vec![0u32];
        starts.extend(
            src.bytes()
                .enumerate()
                .filter(|&(_, b)| b == b'\n')
                .map(|(i, _)| i as u32 + 1),
        );
        LineIndex { starts }
    }

    /// The zero-based line containing a byte offset, and the offset of its start.
    fn line_of(&self, offset: usize) -> (u32, u32) {
        let offset = offset as u32;
        // partition_point is the binary search; the line is the last start at or
        // before the offset.
        let line = self.starts.partition_point(|&s| s <= offset).saturating_sub(1);
        (line as u32, self.starts[line])
    }

    pub fn position(&self, offset: usize) -> Position {
        let (line, start) = self.line_of(offset);
        Position::new(line, offset as u32 - start)
    }

    /// A half-open span from two byte offsets.
    pub fn range(&self, start: usize, end: usize) -> Range {
        Range::new(self.position(start), self.position(end))
    }
}

/// How a client counts columns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    /// Byte offsets, which is what the parsers produce natively.
    Utf8,
    /// UTF-16 code units, the LSP default.
    Utf16,
}

/// The column of a byte offset within one line, in the given encoding.
pub fn column(line: &str, byte_offset: usize, encoding: Encoding) -> u32 {
    match encoding {
        Encoding::Utf8 => byte_offset as u32,
        Encoding::Utf16 => line
            .get(..byte_offset.min(line.len()))
            .unwrap_or(line)
            .chars()
            .map(|c| c.len_utf16() as u32)
            .sum(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_are_zero_based() {
        let src = "one\ntwo\nthree\n";
        let index = LineIndex::new(src);
        assert_eq!(index.position(0), Position::new(0, 0));
        assert_eq!(index.position(2), Position::new(0, 2));
        // The newline itself belongs to the line it ends.
        assert_eq!(index.position(3), Position::new(0, 3));
        assert_eq!(index.position(4), Position::new(1, 0));
        assert_eq!(index.position(8), Position::new(2, 0));
    }

    #[test]
    fn a_file_with_no_trailing_newline_still_indexes() {
        let index = LineIndex::new("a\nb");
        assert_eq!(index.position(2), Position::new(1, 0));
    }

    #[test]
    fn utf16_columns_count_astral_characters_as_two() {
        // A four-byte emoji is one char, two UTF-16 code units, four bytes.
        let line = "\"🦀name\"";
        assert_eq!(column(line, 5, Encoding::Utf8), 5);
        assert_eq!(column(line, 5, Encoding::Utf16), 3);
    }

    #[test]
    fn an_offset_past_the_line_clamps() {
        assert_eq!(column("ab", 99, Encoding::Utf16), 2);
    }
}
