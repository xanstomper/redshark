// Package logo holds the RedShark ASCII logo and shark mascot rendered at
// startup, in the "about" command, and as the TUI splash screen.
//
// The shark silhouette is the Unicode braille-art original from the
// "redshark ascii art" file. The REDSHARK block-text banner sits below it.
// Together they form the full mascot that appears whenever the TUI starts.
package logo

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// ── Semantic palette ───────────────────────────────────────────────────
// Follows Anthology Ch.14 theming: every color is named, not ad-hoc hex.
var (
	// Primary — used for the brand name, header bar, key accents.
	Primary    = lipgloss.Color("#E8443A")
	PrimaryHi  = lipgloss.Color("#FF4C4C")
	PrimaryDim = lipgloss.Color("#8B1A1A")

	// Accent — contrast colour for scope tags, status chips, spinners.
	Accent    = lipgloss.Color("#00CED1")
	AccentDim = lipgloss.Color("#007A7A")

	// Surface — panel/pane background tints.
	Surface    = lipgloss.Color("#000000")
	SurfaceAlt = lipgloss.Color("#000000")

	// Neutral — muted text, borders, dividers.
	Neutral    = lipgloss.Color("#6B6B6B")
	NeutralHi  = lipgloss.Color("#AAAAAA")
	NeutralDim = lipgloss.Color("#444444")

	// Semantic — danger/success/warning for tool output.
	Danger  = lipgloss.Color("#FF4444")
	Success = lipgloss.Color("#89FF69")
	Warning = lipgloss.Color("#FFD700")
)

// BrightRed and Red and Cyan are exported aliases for use by other packages.
var (
	Red       = Primary
	BrightRed = PrimaryHi
	Cyan      = Accent
)

// ── Shark mascot (braille-art) ─────────────────────────────────────────
// This is the original Unicode braille-art shark silhouette from the
// operator's "redshark ascii art" file — the full-body swimming shark.
// It is the primary visual identity for RedShark and appears in the
// splash screen above the block-text banner.
const sharkSilhouette = `⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣠⣤⣤⠶⠶⠶⠶⠾⠛⠛⠛⠛⠛⠛⠛⢿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣶⣿⣛⠛⠛⠛⠓⠢⢄⡀⠀⠤⠟⠂⠀⠀⠀⠀⠀⠀⢀⡿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⠾⠛⠉⠑⠤⣙⢮⡉⠓⣦⣄⡀⠀⣹⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⡶⠞⠋⠉⠀⠀⠀⠀⠀⠀⠒⠛⠛⠛⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⢰⡟⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡴⠾⠛⠉⣡⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⢺⢿⢉⡽⡟⢓⣶⠦⢤⣀⡀⠈⠳⣿⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣀⡴⠟⠁⠀⠀⣀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡤⠚⠁⠀⢛⠛⠛⠻⢷⡧⣾⡴⣛⣏⣹⡇⣀⣿⠀⠀
⠀⠀⠀⠀⠀⠀⣠⠞⠋⠀⣀⠤⠒⢉⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠔⠋⠀⣀⠴⠚⠛⠛⠯⡑⠂⠀⠀⡏⢹⣿⡾⠟⠋⠁⠀⠀
⠀⠀⠀⠀⣠⠞⠁⠀⠐⠊⠀⠀⢠⡿⠁⠀⢰⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡏⣤⡿⠋⠀⠀⠀⠀⠀⠀⡹⠀⠀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀
⠀⠀⣠⡞⠁⠀⠀⠀⠀⠀⠀⢠⡿⠁⢀⢸⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⡞⠋⠉⠉⠓⠒⠢⢤⣴⣥⣆⣠⡾⠋⠀⠀⠀⣦⠀⠀⠀⠀
⠀⣼⠋⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀⠀⢸⠀⡆⢧⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⢽⣦⠀⠀⠀⠀⠀⠀⣟⡿⣽⡏⠀⠀⠀⠀⠀⡿⣧⠀⠀⠀
⢸⣇⣤⣤⣤⣤⣄⡀⠀⢀⡾⠁⠀⠀⢘⡆⠱⡈⢆⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⢻⡚⡆⣀⠀⠀⠀⢸⡽⣿⠃⠀⠀⠀⠀⠀⡇⢹⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠙⢷⣾⠃⠀⠀⠀⠈⠾⣦⣙⠪⢷⠄⠀⠀⠀⠀⠀⠀⠀⠈⠻⣭⣟⣹⢦⣀⣀⣟⣹⡟⠀⠀⠀⠀⠀⠀⡇⠈⣷⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠀⠀⣤⠶⠖⠊⠉⠀⠉⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠦⣼⣞⣹⣯⠟⠁⠀⠀⠀⠀⠀⠀⡇⠀⢹⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⡾⠁⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢐⣲⡾⠟⠛⠳⣤⡀⠀⠀⠀⠀⠀⠀⡇⠀⣸⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⡟⠁⠀⠀⠀⠀⠀⠀⣼⠇⠀⠀⠀⠀⠀⠀⠀⠙⣻⡿⣿⣯⣁⠀⢰⡀⠀⠀⠙⠳⣄⡀⠀⢠⡟⠋⡔⣿⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⠏⠀⠀⠀⠀⠀⠀⢀⡼⠁⠀⠀⠀⠀⠀⠀⠀⢀⠔⠋⢰⠛⢄⠉⠛⠾⣧⡀⠀⠀⠀⠈⠻⣤⣸⡡⠎⢀⡏⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠙⠲⢤⣈⣉⠳⢦⣄⡀⠀⠈⠻⣄⠀⣼⠃⠀⠀
⠀⠀⠀⠀⠀⠀⢰⡟⠀⠀⠀⠀⠀⠀⢠⡾⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠛⠶⣤⡙⣾⠃⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡟⠀⠀⠀⠀⠀⠀⣠⠟⠀⠙⠢⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠟⠻⠇⠀⠀⠀
⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⣀⣤⠾⠻⣦⡀⠀⠀⠀⠈⠑⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⠟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣏⣠⡴⠞⠋⠉⠀⠀⠀⠈⠛⢶⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⣉⣽⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢋⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠒⠶⠶⢤⣤⣤⣤⣤⣤⣤⣤⡤⠴⠶⠖⠚⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀`

// ── Block-text banner ───────────────────────────────────────────────────
// "REDSHARK" in Unicode block characters. The second row is the
// standalone "AGENT" subtitle that sits below the banner when the
// full mascot is displayed.
const bannerBlock = `██████╗ ███████╗██████╗      ███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔════╝██╔══██╗     ██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝
██████╔╝█████╗  ██║  ██║     ███████╗███████║███████║██████╔╝█████╔╝
██╔══██╗██╔══╝  ██║  ██║     ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗
██║  ██║███████╗██████╔╝     ███████║██║  ██║██║  ██║██║  ██║██║  ██╗
╚═╝  ╚═╝╚══════╝╚═════╝      ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝`

const bannerSubtitle = `                   A G E N T`

// ── Compact banner ─────────────────────────────────────────────────────
// For the header bar when the full mascot won't fit. A short red shark
// fin icon + "RedShark" in bold — fits on one line.
const compactBanner = `🦈 RedShark`

// ── Render functions ───────────────────────────────────────────────────

// RenderFullMascot returns the complete shark silhouette + block banner
// + tagline. Used for the splash screen and --version output.
func RenderFullMascot(width int) string {
	var b strings.Builder

	bannerStyle := lipgloss.NewStyle().
		Foreground(Primary).
		Bold(true)

	sharkStyle := lipgloss.NewStyle().
		Foreground(PrimaryDim)

	tagStyle := lipgloss.NewStyle().
		Foreground(Accent)

	subStyle := lipgloss.NewStyle().
		Foreground(NeutralHi)

	// Shark silhouette (dimmed so the block banner pops)
	b.WriteString(sharkStyle.Render(sharkSilhouette))
	b.WriteString("\n")

	// Block-text "REDSHARK" (bright red, bold)
	b.WriteString(bannerStyle.Render(bannerBlock))
	b.WriteString("\n")

	// "A G E N T" subtitle (same style as banner)
	b.WriteString(bannerStyle.Render(bannerSubtitle))
	b.WriteString("\n\n")

	// Tagline
	b.WriteString(tagStyle.Render("  RedShark • Offensive Security Operator"))
	b.WriteString("\n")
	b.WriteString(subStyle.Render("  Built on Bubble Tea v2 • charm.land"))

	return b.String()
}

// Render returns the styled logo for general use. If the terminal is wide
// enough (≥70 cols), it shows the full mascot; otherwise it falls back to
// the compact one-liner.
func Render(width int) string {
	if width >= 70 {
		return RenderFullMascot(width)
	}
	return lipgloss.NewStyle().
		Foreground(Primary).Bold(true).
		Render(compactBanner)
}

// RenderCompact returns just the one-line compact banner for the header.
func RenderCompact() string {
	return lipgloss.NewStyle().
		Foreground(Primary).Bold(true).
		Render(compactBanner)
}

// Separator returns a horizontal divider line styled with the primary
// dim colour. Used between header / chat / input panes.
func Separator(width int) string {
	bar := strings.Repeat("─", max(width, 1))
	return lipgloss.NewStyle().Foreground(NeutralDim).Render(bar)
}

// ScopeBadge renders a scope status chip. Active → accent colour.
// No scope → danger.
func ScopeBadge(label string, active bool) string {
	fg := Accent
	prefix := "◉"
	if !active {
		fg = Danger
		prefix = "○"
	}
	return lipgloss.NewStyle().Foreground(fg).Render(prefix + " " + label)
}
