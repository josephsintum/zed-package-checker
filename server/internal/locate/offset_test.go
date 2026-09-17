package locate

import "testing"

func TestColumn(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		byteOffset  int
		utf8, utf16 int
	}{
		{name: "ascii", line: `  "lodash"`, byteOffset: 9, utf8: 9, utf16: 9},
		{name: "two-byte rune", line: `"café"`, byteOffset: 6, utf8: 6, utf16: 5},
		{name: "three-byte rune", line: `"a☕"`, byteOffset: 5, utf8: 5, utf16: 3},
		// Outside the basic multilingual plane: one rune, two UTF-16 units.
		{name: "surrogate pair", line: `"𝄞"`, byteOffset: 5, utf8: 5, utf16: 3},
		{name: "past the end clamps", line: `ab`, byteOffset: 99, utf8: 2, utf16: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Column([]byte(tt.line), tt.byteOffset, UTF8); got != tt.utf8 {
				t.Errorf("UTF8 column = %d, want %d", got, tt.utf8)
			}
			if got := Column([]byte(tt.line), tt.byteOffset, UTF16); got != tt.utf16 {
				t.Errorf("UTF16 column = %d, want %d", got, tt.utf16)
			}
		})
	}
}
