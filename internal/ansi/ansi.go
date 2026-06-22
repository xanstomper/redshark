// Package ansi offers minimal ANSI helpers used across the TUI.
//
// We do not pull in glamour/lipgloss here on purpose: this package is the
// lowest layer below them and must remain dependency-free so it can be
// imported anywhere without cycles.
package ansi

import (
	"fmt"
	"strings"
)

// Strip removes ANSI escape sequences from s. It is intentionally minimal —
// the only sequences we strip are CSI (\x1b[) and OSC (\x1b]) terminated by
// ST (either \x1b\\ or BEL). That covers everything lipgloss/glamour emit in
// narrow terminals.
func Strip(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if c == 0x1b && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '[':
				// CSI: ESC [ ... letter
				j := i + 2
				for j < len(s) {
					b2 := s[j]
					if b2 >= '@' && b2 <= '~' {
						j++
						break
					}
					j++
				}
				i = j
				continue
			case ']':
				// OSC: ESC ] ... (BEL | ESC \)
				j := i + 2
				for j < len(s) {
					if s[j] == 0x07 {
						j++
						break
					}
					if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
						j += 2
						break
					}
					j++
				}
				i = j
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// VisibleLen returns the visible (non-escape) length of s. Used by layouts
// that need to measure text without leaking ANSI bytes into width math.
func VisibleLen(s string) int { return len(Strip(s)) }

// Truncate returns s shortened to width visible runes, appending an ellipsis
// if any bytes were dropped. ANSI codes inside s are preserved.
func Truncate(s string, width int) string {
	if VisibleLen(s) <= width {
		return s
	}
	if width < 1 {
		return ""
	}
	stripped := Strip(s)
	if len(stripped) <= width {
		return s
	}
	return fmt.Sprintf("%s…", stripped[:width-1])
}
