// Package model implements the main Bubble Tea v2 model for RedShark.
//
// Layout:
//
//	┌────────────────────────────────────┐
//	│ header (brand + scope status)      │  ← logo.RenderCompact + scope badge
//	├────────────────────────────────────┤
//	│  chat messages (scrollable)        │  ← viewport with scroll tracking
//	│  …                                 │
//	├────────────────────────────────────┤
//	│ separator                          │
//	├────────────────────────────────────┤
//	│ input bar                          │  ← prompt + text + cursor
//	└────────────────────────────────────┘
package model

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	agentpkg "github.com/xanstomper/redteam-agent/internal/agent"
	"github.com/xanstomper/redteam-agent/internal/ansi"
	"github.com/xanstomper/redteam-agent/internal/msg"
	"github.com/xanstomper/redteam-agent/internal/scope"
	"github.com/xanstomper/redteam-agent/internal/ui/logo"
	"github.com/xanstomper/redteam-agent/internal/version"
)

const (
	inputHeight    = 1
	headerHeight   = 1
	separatorCount = 2
	minChatHeight  = 3
)

// MainModel is the root Bubble Tea v2 model.
type MainModel struct {
	coordinator  *agentpkg.Coordinator
	scope        *scope.Store
	session      *msg.Session
	width        int
	height       int
	input        string
	inputHistory []string
	historyIdx   int
	historySaved string
	messages     []msg.Message
	loading      bool
	scrollOffset int
	showSplash   bool
	splashTimer  int
	ctx          context.Context
	cancel       context.CancelFunc
}

// New creates the main model.
func New(coord *agentpkg.Coordinator, scopeStore *scope.Store, session *msg.Session) *MainModel {
	ctx, cancel := context.WithCancel(context.Background())
	return &MainModel{
		coordinator:  coord,
		scope:        scopeStore,
		session:      session,
		ctx:          ctx,
		cancel:       cancel,
		historyIdx:   -1,
		scrollOffset: 0,
		showSplash:   true,
		splashTimer:  12,
	}
}

// Init implements tea.Model.
func (m *MainModel) Init() tea.Cmd {
	if m.showSplash {
		return m.tickSplash()
	}
	return nil
}

// tickSplash returns a command that fires a timer-based tick. The model
// counts down splashTimer frames and hides the splash when it hits zero.
func (m *MainModel) tickSplash() tea.Cmd {
	if m.splashTimer <= 0 {
		m.showSplash = false
		return nil
	}
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return splashTick{}
	})
}

// splashTick is a sentinel message fired by the splash timer.
type splashTick struct{}

// Update implements tea.Model.
func (m *MainModel) Update(tmsg tea.Msg) (tea.Model, tea.Cmd) {
	switch tmsg := tmsg.(type) {
	case tea.WindowSizeMsg:
		m.width = tmsg.Width
		m.height = tmsg.Height
		if m.scrollOffset > 0 {
			m.scrollOffset = m.clampScroll(m.scrollOffset)
		}
		if m.showSplash {
			m.splashTimer = 8
		}
		return m, m.tickSplash()

	case tea.KeyPressMsg:
		if m.showSplash {
			m.showSplash = false
			return m, nil
		}
		return m.handleKey(tmsg)

	case tea.PasteMsg:
		if m.showSplash {
			m.showSplash = false
		}
		m.input += string(tmsg.Content)
		m.historyIdx = -1
		return m, nil

	case pasteMsg:
		m.input += tmsg.text
		m.historyIdx = -1
		return m, nil

	case agentResultMsg:
		return m.handleAgentResult(tmsg)

	case scopeStatusResultMsg:
		m.messages = append(m.messages, msg.Message{
			Role:    msg.RoleSystem,
			Content: tmsg.text,
		})
		m.scrollToBottom()
		return m, nil

	case scopeLoadResultMsg:
		if tmsg.err != nil {
			m.messages = append(m.messages, msg.Message{
				Role:    msg.RoleSystem,
				Content: fmt.Sprintf("scope load error: %v", tmsg.err),
			})
		} else {
			m.messages = append(m.messages, msg.Message{
				Role:    msg.RoleSystem,
				Content: fmt.Sprintf("scope loaded: %s (expires %s)", tmsg.scopeID, tmsg.expires.Format("2006-01-02")),
			})
		}
		m.scrollToBottom()
		return m, nil

	case tea.MouseMsg:
		return m.handleMouseMsg(tmsg)

	// Splash auto-dismiss.
	case splashTick:
		m.splashTimer--
		if m.splashTimer <= 0 {
			m.showSplash = false
			return m, nil
		}
		return m, m.tickSplash()
	}

	return m, nil
}

// View implements tea.Model.
func (m *MainModel) View() tea.View {
	if m.width == 0 {
		return tea.NewView("loading...")
	}

	if m.showSplash {
		v := tea.NewView(logo.RenderFullMascot(m.width))
		v.AltScreen = true
		return v
	}

	availHeight := m.height - headerHeight - footerHeight - separatorCount - inputHeight
	if availHeight < minChatHeight {
		availHeight = minChatHeight
	}

	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n")
	b.WriteString(m.renderChat(availHeight))
	chatLines := m.chatLines(availHeight)
	// Pad remaining space to keep footer at constant position
	b.WriteString(strings.Repeat("\n", availHeight-chatLines))
	b.WriteString(m.renderFooter())
	b.WriteString(m.renderSeparator())
	b.WriteString(m.renderInput())

	inputStartY := headerHeight + availHeight + footerHeight + separatorCount

	v := tea.NewView(b.String())
	v.AltScreen = true
	v.MouseMode = tea.MouseModeNone
	v.WindowTitle = "RedShark Offensive Security Operator"
	v.Cursor = m.newCursor(inputStartY, m.cursorX())
	v.OnMouse = m.handleMouse
	return v
}

// handleKey processes keyboard input.
func (m *MainModel) handleKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "ctrl+c", "ctrl+d":
		m.cancel()
		return m, tea.Quit

	case "enter":
		if strings.TrimSpace(m.input) == "" {
			return m, nil
		}
		cmd := strings.TrimSpace(m.input)
		rawInput := m.input
		m.inputHistory = append(m.inputHistory, m.input)
		if len(m.inputHistory) > 100 {
			m.inputHistory = m.inputHistory[len(m.inputHistory)-100:]
		}
		m.historyIdx = -1
		m.input = ""

		switch {
		case cmd == "/scope":
			return m, m.handleScopeStatus()
		case cmd == "/clear":
			m.messages = nil
			m.scrollOffset = 0
			return m, nil
		case cmd == "/quit", cmd == "/exit":
			m.cancel()
			return m, tea.Quit
		case cmd == "/version":
			return m, m.handleVersion()
		case cmd == "/help":
			m.messages = append(m.messages, msg.Message{
				Role:    msg.RoleSystem,
				Content: helpText,
			})
			m.scrollToBottom()
			return m, nil
		case strings.HasPrefix(cmd, "/scope load "):
			path := strings.TrimPrefix(cmd, "/scope load ")
			return m, m.handleScopeLoad(path)
		case strings.HasPrefix(cmd, "/"):
			m.messages = append(m.messages, msg.Message{
				Role:    msg.RoleSystem,
				Content: fmt.Sprintf("unknown command: %s", cmd),
			})
			m.scrollToBottom()
			return m, nil
		default:
			return m.handleUserInput(rawInput)
		}

	case "up":
		if len(m.inputHistory) == 0 {
			return m, nil
		}
		if m.historyIdx == -1 {
			m.historyIdx = len(m.inputHistory) - 1
		} else if m.historyIdx > 0 {
			m.historyIdx--
		}
		if m.historyIdx >= 0 && m.historyIdx < len(m.inputHistory) {
			m.input = m.inputHistory[m.historyIdx]
		}
		return m, nil

	case "down":
		if m.historyIdx == -1 {
			return m, nil
		}
		if m.historyIdx < len(m.inputHistory)-1 {
			m.historyIdx++
			m.input = m.inputHistory[m.historyIdx]
		} else {
			m.historyIdx = -1
			m.input = ""
		}
		return m, nil

	case "ctrl+l":
		m.messages = nil
		m.scrollOffset = 0
		return m, nil

	case "ctrl+k":
		m.input = ""
		m.historyIdx = -1
		return m, nil

	case "ctrl+a":
		m.input = ""
		return m, nil

	case "pageup":
		avail := m.height - headerHeight - separatorCount - inputHeight
		m.scrollOffset = m.clampScroll(m.scrollOffset + avail/2)
		return m, nil

	case "pagedown":
		m.scrollOffset = m.clampScroll(m.scrollOffset - 1)
		if m.scrollOffset == 0 {
			m.scrollToBottom()
		}
		return m, nil

	case "backspace":
		if len(m.input) > 0 {
			_, size := utf8.DecodeLastRuneInString(m.input)
			m.input = m.input[:len(m.input)-size]
		}
		m.historyIdx = -1
		return m, nil

	default:
		ch := k.String()
		if len(ch) == 1 && ch >= " " && ch <= "~" {
			m.input += ch
			m.historyIdx = -1
		} else if len(k.Text) == 1 {
			r, _ := utf8.DecodeRuneInString(k.Text)
			if r != 0 && r != utf8.RuneError {
				m.input += string(r)
				m.historyIdx = -1
			}
		}
		return m, nil
	}
}

// newCursor creates a cursor at the given Y position and X offset.
func (m *MainModel) newCursor(y, x int) *tea.Cursor {
	c := tea.NewCursor(x, y)
	c.Shape = tea.CursorBlock
	c.Color = logo.Primary
	return c
}

// cursorX computes the X cursor position within the input line.
func (m *MainModel) cursorX() int {
	prefix := "❯ "
	if s := m.scope.Active(); s != nil {
		prefix = "[" + s.ID + "] ❯ "
	}
	return len(prefix) + len(m.input)
}

func (m *MainModel) handleAgentResult(tmsg agentResultMsg) (tea.Model, tea.Cmd) {
	m.loading = false
	if tmsg.err != nil {
		m.messages = append(m.messages, msg.Message{
			Role:    msg.RoleSystem,
			Content: fmt.Sprintf("error: %v", tmsg.err),
		})
	} else {
		m.messages = append(m.messages, tmsg.msgs...)
	}
	m.scrollToBottom()
	return m, nil
}

// renderHeader draws the top bar with brand, scope status, and key info.
// Follows Anthology Ch.14: high-contrast header with semantic colors.
func (m *MainModel) renderHeader() string {
	scopeID := "no-scope"
	scopeActive := false
	if s := m.scope.Active(); s != nil {
		scopeID = s.ID
		scopeActive = true
	}

	brand := lipgloss.NewStyle().Foreground(logo.Primary).Bold(true).Render("🦈 RedShark")
	badge := logo.ScopeBadge(scopeID, scopeActive)
	versionStr := lipgloss.NewStyle().Foreground(logo.NeutralDim).Render(version.Short())

	// Right-aligned: message count and a hint
	msgCount := len(m.messages)
	statusStr := lipgloss.NewStyle().Foreground(logo.NeutralDim).Render(fmt.Sprintf("%d msgs", msgCount))
	if m.loading {
		statusStr = lipgloss.NewStyle().Foreground(logo.Accent).Render("◌ running...")
	}

	left := brand + "  " + badge
	right := statusStr + "  " + versionStr

	// Pad to fill width
	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	middlePad := max(m.width-leftWidth-rightWidth, 0)
	full := left + strings.Repeat(" ", middlePad) + right

	headerStyle := lipgloss.NewStyle().
		Width(m.width).
		Background(logo.Surface).
		PaddingLeft(1).
		PaddingRight(1)

	return headerStyle.Render(full)
}

// chatPaneStyle returns the bordered style for the chat area.
func (m *MainModel) chatPaneStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(logo.NeutralDim).
		Padding(1).
		Width(m.width - 2).
		Height(max(m.height-headerHeight-footerHeight-separatorCount-inputHeight-2, minChatHeight))
}

// footerHeight accounts for the keybind hint bar.
const footerHeight = 1

// renderChat draws the scrollable message area inside a bordered pane.
func (m *MainModel) renderChat(maxLines int) string {
	if len(m.messages) == 0 && !m.loading {
		emptyText := "RedShark ready. Load a scope to begin.\nType /help for available commands."
		emptyStyle := lipgloss.NewStyle().Foreground(logo.Neutral).Italic(true)
		return m.chatPaneStyle().Render(emptyStyle.Render(emptyText))
	}

	var lines []string
	for i := range m.messages {
		lines = append(lines, m.formatMessage(&m.messages[i]))
	}

	start := 0
	totalLines := len(lines)

	if totalLines > maxLines && m.scrollOffset > 0 {
		start = m.scrollOffset
	} else if totalLines > maxLines {
		start = max(0, totalLines-maxLines)
	}

	var outLines []string
	for i := start; i < totalLines && (i-start) < maxLines; i++ {
		outLines = append(outLines, lines[i])
	}

	if totalLines > maxLines {
		if m.scrollOffset > 0 {
			outLines = append(outLines, lipgloss.NewStyle().Foreground(logo.NeutralDim).Render("  ▲ more above"))
		}
		remaining := totalLines - (start + maxLines)
		if remaining > 0 {
			outLines = append(outLines, lipgloss.NewStyle().Foreground(logo.NeutralDim).Render(fmt.Sprintf("  ▼ %d more below", remaining)))
		}
	}

	chatContent := strings.Join(outLines, "\n")
	return m.chatPaneStyle().Render(chatContent)
}

// formatMessage renders a single message with role-appropriate styling.
func (m *MainModel) formatMessage(mm *msg.Message) string {
	content := mm.Content
	if len(content) > m.width-4 {
		content = ansi.Truncate(content, m.width-4)
	}

	switch mm.Role {
	case msg.RoleUser:
		prefixStyle := lipgloss.NewStyle().Foreground(logo.PrimaryHi).Bold(true)
		textStyle := lipgloss.NewStyle().Foreground(logo.NeutralHi)
		return prefixStyle.Render("❯ ") + textStyle.Render(content)

	case msg.RoleAssistant:
		prefixStyle := lipgloss.NewStyle().Foreground(logo.Accent)
		textStyle := lipgloss.NewStyle().Foreground(logo.NeutralHi)
		return prefixStyle.Render("🦈 ") + textStyle.Render(content)

	case msg.RoleTool:
		toolName := mm.ToolName
		if mm.Refused {
			prefixStyle := lipgloss.NewStyle().Foreground(logo.Danger).Bold(true)
			textStyle := lipgloss.NewStyle().Foreground(logo.Danger)
			toolBadge := lipgloss.NewStyle().
				Foreground(logo.Danger).
				Background(logo.SurfaceAlt).
				Render(" ⛔ TOOL REFUSED ")
			header := prefixStyle.Render("── ") + toolBadge + prefixStyle.Render(" ──")
			return header + "\n" + textStyle.Render("  "+content)
		}
		toolBadge := lipgloss.NewStyle().
			Foreground(logo.Neutral).
			Background(logo.SurfaceAlt).
			Render(" ⚡ " + strings.ToUpper(toolName) + " ")
		toolLine := lipgloss.NewStyle().Foreground(logo.NeutralDim).Render("──") + toolBadge + lipgloss.NewStyle().Foreground(logo.NeutralDim).Render("──")
		textStyle := lipgloss.NewStyle().Foreground(logo.NeutralHi)
		return toolLine + "\n" + textStyle.Render("  "+content)

	case msg.RoleSystem:
		textStyle := lipgloss.NewStyle().Foreground(logo.Neutral)
		return textStyle.Render("  ℹ " + content)

	default:
		return lipgloss.NewStyle().Foreground(logo.Neutral).Render(content)
	}
}

// renderFooter draws the keybind hint bar above the separator.
func (m *MainModel) renderFooter() string {
	hints := []string{
		"ctrl+c quit",
		"ctrl+l clear",
		"↑↓ history",
		"pgup/pgdn scroll",
	}
	if m.loading {
		hints = append(hints, "◌ running...")
	}
	hintStr := strings.Join(hints, " │ ")
	footerStyle := lipgloss.NewStyle().
		Foreground(logo.NeutralDim).
		PaddingLeft(1).
		Width(m.width)
	return footerStyle.Render(hintStr)
}

// renderSeparator draws the horizontal divider between chat and input.
func (m *MainModel) renderSeparator() string {
	sep := strings.Repeat("─", max(m.width, 1))
	return lipgloss.NewStyle().Foreground(logo.NeutralDim).Render(sep)
}

// renderInput draws the input prompt line.
func (m *MainModel) renderInput() string {
	prompt := "❯ "
	if s := m.scope.Active(); s != nil {
		prompt = "[" + s.ID + "] ❯ "
	}

	if m.loading {
		loadingStyle := lipgloss.NewStyle().Foreground(logo.Accent)
		return loadingStyle.Render("  ◌ running tool...")
	}

	promptStyle := lipgloss.NewStyle().Foreground(logo.Primary).Bold(true)
	inputStyle := lipgloss.NewStyle().Foreground(logo.NeutralHi)
	return promptStyle.Render(prompt) + inputStyle.Render(m.input)
}

// chatLines returns how many lines the chat content occupies.
func (m *MainModel) chatLines(maxLines int) int {
	if len(m.messages) == 0 {
		return 1
	}
	lines := 0
	for _, mm := range m.messages {
		lines += 1 + strings.Count(mm.Content, "\n")
		if lines >= maxLines {
			return maxLines
		}
	}
	return min(lines, maxLines)
}

// scrollToBottom resets scroll to show the latest messages.
func (m *MainModel) scrollToBottom() {
	m.scrollOffset = 0
}

// clampScroll keeps scroll offset within valid range.
func (m *MainModel) clampScroll(offset int) int {
	totalLines := 0
	for _, mm := range m.messages {
		totalLines += 1 + strings.Count(mm.Content, "\n")
	}
	availHeight := m.height - headerHeight - separatorCount - inputHeight
	maxScroll := max(0, totalLines-availHeight)
	if offset < 0 {
		return 0
	}
	if offset > maxScroll {
		return maxScroll
	}
	return offset
}

// handleUserInput sends user text to the agent coordinator.
func (m *MainModel) handleUserInput(content string) (tea.Model, tea.Cmd) {
	m.messages = append(m.messages, msg.Message{
		Role: msg.RoleUser, Content: content, Timestamp: time.Now().UTC(),
	})
	m.loading = true
	return m, func() tea.Msg {
		result, err := m.coordinator.HandleUserMessage(m.ctx, content)
		return agentResultMsg{msgs: result, err: err}
	}
}

func (m *MainModel) handleScopeStatus() tea.Cmd {
	return func() tea.Msg {
		s := m.scope.Active()
		if s == nil {
			return scopeStatusResultMsg{text: "No scope loaded. Use /scope load <path>"}
		}
		return scopeStatusResultMsg{text: fmt.Sprintf(
			"Scope: %s | Operator: %s | Sponsor: %s | Expires: %s | Network: %d | Techniques: %v",
			s.ID, s.Operator, s.Sponsor, s.Expires.Format("2006-01-02"), len(s.Network), s.Techniques)}
	}
}

func (m *MainModel) handleScopeLoad(path string) tea.Cmd {
	return func() tea.Msg {
		sc, err := scope.LoadFile(path)
		if err != nil {
			return scopeLoadResultMsg{err: err}
		}
		if err := m.scope.Load(sc); err != nil {
			return scopeLoadResultMsg{err: err}
		}
		return scopeLoadResultMsg{scopeID: sc.ID, expires: sc.Expires}
	}
}

func (m *MainModel) handleVersion() tea.Cmd {
	return func() tea.Msg {
		return scopeStatusResultMsg{text: version.String()}
	}
}

// handleMouse is the OnMouse callback on the View. It intercepts mouse
// events in the rendered view for scroll wheel navigation.
func (m *MainModel) handleMouse(msg tea.MouseMsg) tea.Cmd {
	availHeight := m.height - headerHeight - separatorCount - inputHeight
	scrollStep := availHeight / 3
	if scrollStep < 1 {
		scrollStep = 1
	}
	button := msg.Mouse().Button
	switch {
	case button == 4:
		m.scrollOffset = m.clampScroll(m.scrollOffset + scrollStep)
	case button == 5:
		m.scrollOffset = m.clampScroll(m.scrollOffset - scrollStep)
		if m.scrollOffset == 0 {
			m.scrollToBottom()
		}
	}
	return nil
}

// handleMouseMsg handles Bubble Tea mouse messages from the input stream.
func (m *MainModel) handleMouseMsg(tmsg tea.MouseMsg) (tea.Model, tea.Cmd) {
	availHeight := m.height - headerHeight - separatorCount - inputHeight
	scrollStep := availHeight / 3
	if scrollStep < 1 {
		scrollStep = 1
	}
	button := tmsg.Mouse().Button
	switch {
	case button == 4:
		m.scrollOffset = m.clampScroll(m.scrollOffset + scrollStep)
	case button == 5:
		m.scrollOffset = m.clampScroll(m.scrollOffset - scrollStep)
		if m.scrollOffset == 0 {
			m.scrollToBottom()
		}
	}
	return m, nil
}

type pasteMsg struct{ text string }

type agentResultMsg struct {
	msgs []msg.Message
	err  error
}

type scopeStatusResultMsg struct{ text string }

type scopeLoadResultMsg struct {
	scopeID string
	expires time.Time
	err     error
}

var helpText = `Available commands:
  /scope                — show loaded scope status
  /scope load <path>    — load a scope file
  /clear                — clear chat history
  /version              — show version info
  /help                 — show this help
  /quit, /exit          — quit RedShark

Key shortcuts:
  ↑/↓     — navigate input history
  Ctrl+U  — clear input line
  Ctrl+L  — clear chat
  Ctrl+C  — quit
`

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
