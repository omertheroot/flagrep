package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// Match represents a single search result for TUI display
type Match struct {
	File     string
	Decoders []string
	Match    string
	Context  string
	Offset   int
}

// TUI provides an interactive terminal interface for browsing results
type TUI struct {
	matches       []Match
	filteredIdx   []int // Indices into matches for filtered view
	currentIndex  int
	pageSize      int
	running       bool
	searchMode    bool
	searchQuery   string
	helpMode      bool
	statusMessage string
	oldTermios    syscall.Termios
	searchHistory []string
}

// NewTUI creates a new TUI instance
func NewTUI(matches []Match) *TUI {
	indices := make([]int, len(matches))
	for i := range matches {
		indices[i] = i
	}
	return &TUI{
		matches:      matches,
		filteredIdx:  indices,
		currentIndex: 0,
		pageSize:     8,
		running:      true,
	}
}

const (
	clearScreen    = "\033[2J"
	moveCursor     = "\033[H"
	clearLine      = "\033[2K"
	saveCursor     = "\033[s"
	restoreCursor  = "\033[u"
	hideCursor     = "\033[?25l"
	showCursor     = "\033[?25h"
	colorRed       = "\033[31m"
	colorGreen     = "\033[32m"
	colorYellow    = "\033[33m"
	colorBlue      = "\033[34m"
	colorMagenta   = "\033[35m"
	colorCyan      = "\033[36m"
	colorWhite     = "\033[37m"
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
	colorUnderline = "\033[4m"
	colorReverse   = "\033[7m"
	bgBlue         = "\033[44m"
	bgGreen        = "\033[42m"
	bgRed          = "\033[41m"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func getTerminalSize() (int, int) {
	ws := &winsize{}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(ws)))
	if ws.Col == 0 {
		ws.Col = 80
	}
	if ws.Row == 0 {
		ws.Row = 24
	}
	return int(ws.Col), int(ws.Row)
}

func (t *TUI) enableRawMode() {
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t.oldTermios)))
	newTermios := t.oldTermios
	newTermios.Lflag &^= syscall.ICANON | syscall.ECHO
	newTermios.Cc[syscall.VMIN] = 1
	newTermios.Cc[syscall.VTIME] = 0
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&newTermios)))
}

func (t *TUI) disableRawMode() {
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t.oldTermios)))
}

// Run starts the interactive TUI
func (t *TUI) Run() {
	if len(t.matches) == 0 {
		fmt.Println("No matches found.")
		return
	}

	t.enableRawMode()
	defer t.disableRawMode()
	fmt.Print(hideCursor)
	defer fmt.Print(showCursor)

	for t.running {
		if t.helpMode {
			t.renderHelp()
		} else {
			t.render()
		}
		t.handleInput()
	}

	fmt.Print(clearScreen + moveCursor)
}

func (t *TUI) render() {
	width, height := getTerminalSize()
	fmt.Print(clearScreen + moveCursor)

	headerText := fmt.Sprintf(" FLAGREP TUI │ %d/%d matches ", len(t.filteredIdx), len(t.matches))
	if t.searchQuery != "" {
		headerText += fmt.Sprintf("│ Filter: %q ", t.searchQuery)
	}
	// Truncate header if too long
	if len(headerText) > width-4 {
		headerText = headerText[:width-7] + "..."
	}
	padding := (width - len(headerText)) / 2
	if padding < 0 {
		padding = 0
	}
	rightPad := width - len(headerText) - padding
	if rightPad < 0 {
		rightPad = 0
	}
	fmt.Printf("%s%s%s%s%s%s\n", colorBold, bgBlue, colorWhite, strings.Repeat(" ", padding), headerText, strings.Repeat(" ", rightPad))
	fmt.Print(colorReset)

	linesPerItem := 3
	reservedLines := 4 // header (1) + empty line before footer (1) + footer separator (1) + footer (1)
	availableRows := height - reservedLines
	if availableRows < linesPerItem {
		availableRows = linesPerItem
	}
	itemsPerPage := availableRows / linesPerItem
	if itemsPerPage < 1 {
		itemsPerPage = 1
	}
	t.pageSize = itemsPerPage

	startIdx := (t.currentIndex / t.pageSize) * t.pageSize
	endIdx := startIdx + t.pageSize
	if endIdx > len(t.filteredIdx) {
		endIdx = len(t.filteredIdx)
	}

	linesUsed := 1 // header already printed

	if len(t.filteredIdx) == 0 {
		fmt.Printf("\n%s  No matches found for filter: %q%s\n", colorYellow, t.searchQuery, colorReset)
		linesUsed += 2
	} else {
		for i := startIdx; i < endIdx; i++ {
			matchIdx := t.filteredIdx[i]
			match := t.matches[matchIdx]

			// Selection indicator
			if i == t.currentIndex {
				fmt.Printf("%s%s▶%s ", colorBold, colorGreen, colorReset)
			} else {
				fmt.Print("  ")
			}

			// File with number
			fmt.Printf("%s%s[%d]%s %s\n", colorBold, colorYellow, i+1, colorReset, truncate(match.File, width-10))

			// Decoders
			decoderStr := "None"
			if len(match.Decoders) > 0 {
				decoderStr = strings.Join(match.Decoders, " → ")
			}
			fmt.Printf("    %sDecoders:%s %s\n", colorDim, colorReset, truncate(decoderStr, width-15))

			// Context with highlighted match
			context := escapeNewlines(match.Context)
			if len(context) > width-15 {
				context = context[:width-18] + "..."
			}
			highlighted := strings.ReplaceAll(context, match.Match, colorRed+colorBold+match.Match+colorReset)
			fmt.Printf("    %sContext:%s %s\n", colorDim, colorReset, highlighted)

			linesUsed += linesPerItem
		}
	}

	// Fill remaining space to push footer to bottom
	displayedItems := endIdx - startIdx
	expectedLines := itemsPerPage * linesPerItem
	actualContentLines := displayedItems * linesPerItem
	remainingLines := expectedLines - actualContentLines
	for i := 0; i < remainingLines; i++ {
		fmt.Println()
		linesUsed++
	}

	// Status message
	if t.statusMessage != "" {
		fmt.Printf("%s%s %s %s\n", colorBold, bgGreen, t.statusMessage, colorReset)
		t.statusMessage = ""
	} else {
		fmt.Println()
	}

	// Footer
	page := 1
	totalPages := 1
	if len(t.filteredIdx) > 0 {
		page = (t.currentIndex / t.pageSize) + 1
		totalPages = ((len(t.filteredIdx) - 1) / t.pageSize) + 1
	}
	// Footer separator - dynamic width
	separator := strings.Repeat("─", width)
	fmt.Printf("%s%s%s\n", colorDim, separator, colorReset)

	// Footer text - adapt to width
	footerText := fmt.Sprintf(" Page %d/%d │ [j/k] Nav │ [/] Search │ [?] Help │ [q] Quit ", page, totalPages)
	if len(footerText) > width {
		footerText = fmt.Sprintf(" %d/%d │ j/k │ / │ ? │ q ", page, totalPages)
	}
	fmt.Printf("%s%s%s", colorReverse, footerText, colorReset)

	// Search mode prompt
	if t.searchMode {
		fmt.Printf("\n%s/%s", colorGreen, t.searchQuery)
	}
}

func (t *TUI) renderHelp() {
	width, height := getTerminalSize()
	fmt.Print(clearScreen + moveCursor)

	// Header
	headerText := " FLAGREP TUI HELP "
	if len(headerText) > width-4 {
		headerText = " HELP "
	}
	padding := (width - len(headerText)) / 2
	if padding < 0 {
		padding = 0
	}
	rightPad := width - len(headerText) - padding
	if rightPad < 0 {
		rightPad = 0
	}
	fmt.Printf("%s%s%s%s%s\n", colorBold, bgMagenta, strings.Repeat(" ", padding), headerText, strings.Repeat(" ", rightPad))
	fmt.Print(colorReset)
	fmt.Println()

	// Calculate how many lines we can show
	availableLines := height - 5

	if availableLines >= 16 {
		fmt.Printf("%s%sNavigation:%s\n", colorBold, colorCyan, colorReset)
		fmt.Printf("  %sj, ↓%s      Move down\n", colorYellow, colorReset)
		fmt.Printf("  %sk, ↑%s      Move up\n", colorYellow, colorReset)
		fmt.Printf("  %sg%s         Go to first match\n", colorYellow, colorReset)
		fmt.Printf("  %sG%s         Go to last match\n", colorYellow, colorReset)
		fmt.Printf("  %sn, PgDn%s   Next page\n", colorYellow, colorReset)
		fmt.Printf("  %sp, PgUp%s   Previous page\n", colorYellow, colorReset)
		fmt.Println()

		fmt.Printf("%s%sActions:%s\n", colorBold, colorCyan, colorReset)
		fmt.Printf("  %sEnter%s     Expand current match\n", colorYellow, colorReset)
		fmt.Printf("  %s/%s         Search/filter matches\n", colorYellow, colorReset)
		fmt.Printf("  %sEsc%s       Clear search filter\n", colorYellow, colorReset)
		fmt.Printf("  %sh%s         Show hex view of match\n", colorYellow, colorReset)
		fmt.Printf("  %sd%s         Decoder playground\n", colorYellow, colorReset)
		fmt.Printf("  %sy%s         Copy match to clipboard\n", colorYellow, colorReset)
		fmt.Printf("  %so%s         Open file in $EDITOR\n", colorYellow, colorReset)
		fmt.Printf("  %se%s         Export results to file\n", colorYellow, colorReset)
		fmt.Printf("  %s?%s         Toggle this help\n", colorYellow, colorReset)
		fmt.Printf("  %sq%s         Quit\n", colorYellow, colorReset)
		fmt.Println()
	} else {
		// Compact help for small terminals
		fmt.Printf("%sj/k%s:Move %sn/p%s:Page %sg/G%s:Start/End\n", colorYellow, colorReset, colorYellow, colorReset, colorYellow, colorReset)
		fmt.Printf("%s/%s:Search %sEnter%s:Expand %sh%s:Hex %sd%s:Decode\n", colorYellow, colorReset, colorYellow, colorReset, colorYellow, colorReset, colorYellow, colorReset)
		fmt.Printf("%sy%s:Copy %so%s:Edit %se%s:Export %sq%s:Quit\n", colorYellow, colorReset, colorYellow, colorReset, colorYellow, colorReset, colorYellow, colorReset)
		fmt.Println()
	}

	fmt.Printf("%s%sPress any key to return...%s", colorDim, colorReset, colorReset)
}

const bgMagenta = "\033[45m"

// handleInput processes keyboard input
func (t *TUI) handleInput() {
	buf := make([]byte, 3)
	n, err := os.Stdin.Read(buf)
	if err != nil || n == 0 {
		return
	}

	// Handle help mode
	if t.helpMode {
		t.helpMode = false
		return
	}

	// Handle search mode
	if t.searchMode {
		t.handleSearchInput(buf[0])
		return
	}

	// Handle escape sequences (arrow keys, etc.)
	if buf[0] == 27 && n >= 3 {
		switch buf[2] {
		case 'A': // Up arrow
			t.moveUp()
		case 'B': // Down arrow
			t.moveDown()
		case 'C': // Right arrow (expand)
			t.showExpanded()
		case 'D': // Left arrow (go back)
			// No-op in main view
		case '5': // Page Up
			t.prevPage()
		case '6': // Page Down
			t.nextPage()
		}
		return
	}

	// Single key commands
	switch buf[0] {
	case 'q', 'Q':
		t.running = false
	case 'j', 'J':
		t.moveDown()
	case 'k', 'K':
		t.moveUp()
	case 'g':
		t.currentIndex = 0
	case 'G':
		if len(t.filteredIdx) > 0 {
			t.currentIndex = len(t.filteredIdx) - 1
		}
	case '\n', '\r':
		t.showExpanded()
	case 'n', 'N':
		t.nextPage()
	case 'p', 'P':
		t.prevPage()
	case '/':
		t.searchMode = true
		t.searchQuery = ""
	case 27: // Escape - clear filter
		t.clearFilter()
	case '?':
		t.helpMode = true
	case 'y', 'Y':
		t.copyToClipboard()
	case 'o', 'O':
		t.openInEditor()
	case 'e', 'E':
		t.exportResults()
	case 'h', 'H':
		t.showHexView()
	case 'd', 'D':
		t.showDecoderPlayground()
	}
}

func (t *TUI) handleSearchInput(char byte) {
	switch char {
	case 27: // Escape
		t.searchMode = false
	case '\n', '\r': // Enter - apply filter
		t.searchMode = false
		t.applyFilter()
	case 127, 8: // Backspace
		if len(t.searchQuery) > 0 {
			t.searchQuery = t.searchQuery[:len(t.searchQuery)-1]
		}
	default:
		if char >= 32 && char < 127 {
			t.searchQuery += string(char)
		}
	}
}

func (t *TUI) moveUp() {
	if t.currentIndex > 0 {
		t.currentIndex--
	}
}

func (t *TUI) moveDown() {
	if t.currentIndex < len(t.filteredIdx)-1 {
		t.currentIndex++
	}
}

func (t *TUI) nextPage() {
	t.currentIndex += t.pageSize
	if t.currentIndex >= len(t.filteredIdx) {
		t.currentIndex = len(t.filteredIdx) - 1
	}
	if t.currentIndex < 0 {
		t.currentIndex = 0
	}
}

func (t *TUI) prevPage() {
	t.currentIndex -= t.pageSize
	if t.currentIndex < 0 {
		t.currentIndex = 0
	}
}

func (t *TUI) applyFilter() {
	if t.searchQuery == "" {
		t.clearFilter()
		return
	}

	query := strings.ToLower(t.searchQuery)
	t.filteredIdx = make([]int, 0)

	for i, match := range t.matches {
		if strings.Contains(strings.ToLower(match.File), query) ||
			strings.Contains(strings.ToLower(match.Match), query) ||
			strings.Contains(strings.ToLower(match.Context), query) {
			t.filteredIdx = append(t.filteredIdx, i)
		}
	}

	t.currentIndex = 0
	t.statusMessage = fmt.Sprintf("Found %d matches for %q", len(t.filteredIdx), t.searchQuery)
}

func (t *TUI) clearFilter() {
	t.searchQuery = ""
	t.filteredIdx = make([]int, len(t.matches))
	for i := range t.matches {
		t.filteredIdx[i] = i
	}
	t.currentIndex = 0
	t.statusMessage = "Filter cleared"
}

// showExpanded displays full details of the current match
func (t *TUI) showExpanded() {
	if len(t.filteredIdx) == 0 || t.currentIndex >= len(t.filteredIdx) {
		return
	}

	matchIdx := t.filteredIdx[t.currentIndex]
	match := t.matches[matchIdx]
	width, _ := getTerminalSize()

	fmt.Print(clearScreen + moveCursor)

	// Header
	headerText := " EXPANDED VIEW "
	padding := (width - len(headerText)) / 2
	fmt.Printf("%s%s%s%s%s\n", colorBold, bgMagenta, strings.Repeat(" ", padding), headerText, strings.Repeat(" ", width-len(headerText)-padding))
	fmt.Print(colorReset)
	fmt.Println()

	fmt.Printf("%s%sFile:%s %s\n", colorBold, colorYellow, colorReset, match.File)
	fmt.Printf("%s%sOffset:%s %d bytes\n", colorBold, colorYellow, colorReset, match.Offset)
	fmt.Println()

	decoderStr := "None"
	if len(match.Decoders) > 0 {
		decoderStr = strings.Join(match.Decoders, " → ")
	}
	fmt.Printf("%s%sDecoders:%s %s\n", colorBold, colorCyan, colorReset, decoderStr)
	fmt.Println()

	fmt.Printf("%s%sMatch:%s\n", colorBold, colorRed, colorReset)
	fmt.Printf("  %s%s%s\n", colorRed, match.Match, colorReset)
	fmt.Println()

	fmt.Printf("%s%sFull Context:%s\n", colorBold, colorGreen, colorReset)
	// Word wrap context
	context := match.Context
	lines := strings.Split(context, "\n")
	for _, line := range lines {
		if len(line) > width-4 {
			for len(line) > width-4 {
				fmt.Printf("  %s\n", line[:width-4])
				line = line[width-4:]
			}
		}
		fmt.Printf("  %s\n", line)
	}

	fmt.Println()
	fmt.Printf("%s%sPress any key to return...%s", colorDim, colorReset, colorReset)

	// Wait for any key
	buf := make([]byte, 1)
	os.Stdin.Read(buf)
}

func (t *TUI) copyToClipboard() {
	if len(t.filteredIdx) == 0 || t.currentIndex >= len(t.filteredIdx) {
		return
	}

	matchIdx := t.filteredIdx[t.currentIndex]
	match := t.matches[matchIdx]

	// Try xclip, xsel, or wl-copy
	var cmd *exec.Cmd
	if _, err := exec.LookPath("xclip"); err == nil {
		cmd = exec.Command("xclip", "-selection", "clipboard")
	} else if _, err := exec.LookPath("xsel"); err == nil {
		cmd = exec.Command("xsel", "--clipboard", "--input")
	} else if _, err := exec.LookPath("wl-copy"); err == nil {
		cmd = exec.Command("wl-copy")
	} else {
		t.statusMessage = "No clipboard tool found (xclip/xsel/wl-copy)"
		return
	}

	cmd.Stdin = strings.NewReader(match.Match)
	if err := cmd.Run(); err != nil {
		t.statusMessage = "Failed to copy to clipboard"
	} else {
		t.statusMessage = fmt.Sprintf("Copied: %s", truncate(match.Match, 30))
	}
}

func (t *TUI) openInEditor() {
	if len(t.filteredIdx) == 0 || t.currentIndex >= len(t.filteredIdx) {
		return
	}

	matchIdx := t.filteredIdx[t.currentIndex]
	match := t.matches[matchIdx]

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vim"
	}

	// Restore terminal
	t.disableRawMode()
	fmt.Print(showCursor)
	fmt.Print(clearScreen + moveCursor)

	// Open editor
	cmd := exec.Command(editor, match.File)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	// Restore raw mode
	t.enableRawMode()
	fmt.Print(hideCursor)
}

func (t *TUI) exportResults() {
	// Restore terminal temporarily for filename input
	t.disableRawMode()
	fmt.Print(showCursor)
	fmt.Print(clearScreen + moveCursor)

	fmt.Print("Export filename: ")
	reader := bufio.NewReader(os.Stdin)
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	if filename == "" {
		filename = "flagrep_results.txt"
	}

	file, err := os.Create(filename)
	if err != nil {
		t.statusMessage = fmt.Sprintf("Failed to create file: %v", err)
	} else {
		defer file.Close()
		for _, idx := range t.filteredIdx {
			match := t.matches[idx]
			decoderStr := "None"
			if len(match.Decoders) > 0 {
				decoderStr = strings.Join(match.Decoders, " -> ")
			}
			fmt.Fprintf(file, "File: %s\nDecoders: %s\nMatch: %s\nContext: %s\nOffset: %d\n\n",
				match.File, decoderStr, match.Match, match.Context, match.Offset)
		}
		t.statusMessage = fmt.Sprintf("Exported %d results to %s", len(t.filteredIdx), filename)
	}

	// Restore raw mode
	t.enableRawMode()
	fmt.Print(hideCursor)
}

// Helper functions
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func escapeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// showHexView displays a hex dump of the current match
func (t *TUI) showHexView() {
	if len(t.filteredIdx) == 0 || t.currentIndex >= len(t.filteredIdx) {
		return
	}

	matchIdx := t.filteredIdx[t.currentIndex]
	match := t.matches[matchIdx]
	width, _ := getTerminalSize()

	fmt.Print(clearScreen + moveCursor)

	// Header
	headerText := " HEX VIEW "
	padding := (width - len(headerText)) / 2
	fmt.Printf("%s%s%s%s%s\n", colorBold, bgBlue, strings.Repeat(" ", padding), headerText, strings.Repeat(" ", width-len(headerText)-padding))
	fmt.Print(colorReset)
	fmt.Println()

	fmt.Printf("%s%sFile:%s %s\n", colorBold, colorYellow, colorReset, match.File)
	fmt.Printf("%s%sOffset:%s %d\n", colorBold, colorYellow, colorReset, match.Offset)
	fmt.Println()

	// Hex dump
	data := []byte(match.Context)
	bytesPerLine := 16

	fmt.Printf("%s%sHex Dump:%s\n", colorBold, colorCyan, colorReset)
	for i := 0; i < len(data); i += bytesPerLine {
		// Offset
		fmt.Printf("%s%08X%s  ", colorDim, i, colorReset)

		// Hex bytes
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				b := data[i+j]
				// Highlight printable ASCII
				if b >= 32 && b <= 126 {
					fmt.Printf("%s%02X%s ", colorGreen, b, colorReset)
				} else {
					fmt.Printf("%02X ", b)
				}
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		fmt.Print(" |")
		// ASCII representation
		for j := 0; j < bytesPerLine && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Printf("%s%c%s", colorGreen, b, colorReset)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}

	fmt.Println()
	fmt.Printf("%s%sPress any key to return...%s", colorDim, colorReset, colorReset)

	buf := make([]byte, 1)
	os.Stdin.Read(buf)
}

// showDecoderPlayground allows manually applying decoders to text
func (t *TUI) showDecoderPlayground() {
	if len(t.filteredIdx) == 0 || t.currentIndex >= len(t.filteredIdx) {
		return
	}

	matchIdx := t.filteredIdx[t.currentIndex]
	match := t.matches[matchIdx]
	width, _ := getTerminalSize()

	// Get available decoders
	decoders := getDecoders()
	decoderNames := make([]string, 0, len(decoders))
	for name := range decoders {
		decoderNames = append(decoderNames, name)
	}

	currentText := match.Context
	selectedDecoder := 0
	history := []string{currentText}

	for {
		fmt.Print(clearScreen + moveCursor)

		// Header
		headerText := " DECODER PLAYGROUND "
		padding := (width - len(headerText)) / 2
		fmt.Printf("%s%s%s%s%s\n", colorBold, bgMagenta, strings.Repeat(" ", padding), headerText, strings.Repeat(" ", width-len(headerText)-padding))
		fmt.Print(colorReset)
		fmt.Println()

		// Current text
		fmt.Printf("%s%sCurrent Text:%s\n", colorBold, colorYellow, colorReset)
		displayText := currentText
		if len(displayText) > 200 {
			displayText = displayText[:200] + "..."
		}
		displayText = escapeNewlines(displayText)
		fmt.Printf("  %s\n\n", displayText)

		// Decoder list
		fmt.Printf("%s%sDecoders:%s (use j/k to select, Enter to apply, u to undo, q to quit)\n", colorBold, colorCyan, colorReset)
		startIdx := (selectedDecoder / 10) * 10
		for i := startIdx; i < startIdx+10 && i < len(decoderNames); i++ {
			prefix := "  "
			if i == selectedDecoder {
				prefix = colorGreen + "▶ " + colorReset
			}
			fmt.Printf("%s%s\n", prefix, decoderNames[i])
		}

		fmt.Println()
		fmt.Printf("%s[j/k] Select  [Enter] Apply  [u] Undo  [c] Copy  [q] Quit%s\n", colorDim, colorReset)

		// Read input
		buf := make([]byte, 3)
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			continue
		}

		switch buf[0] {
		case 'q', 'Q':
			return
		case 'j', 'J':
			if selectedDecoder < len(decoderNames)-1 {
				selectedDecoder++
			}
		case 'k', 'K':
			if selectedDecoder > 0 {
				selectedDecoder--
			}
		case '\n', '\r':
			// Apply selected decoder
			decoderName := decoderNames[selectedDecoder]
			decoder := decoders[decoderName]
			result, err := decoder(currentText)
			if err == nil && result != "" && result != currentText {
				history = append(history, currentText)
				currentText = result
			}
		case 'u', 'U':
			// Undo
			if len(history) > 1 {
				currentText = history[len(history)-1]
				history = history[:len(history)-1]
			}
		case 'c', 'C':
			// Copy current text to clipboard
			var cmd *exec.Cmd
			if _, err := exec.LookPath("xclip"); err == nil {
				cmd = exec.Command("xclip", "-selection", "clipboard")
			} else if _, err := exec.LookPath("xsel"); err == nil {
				cmd = exec.Command("xsel", "--clipboard", "--input")
			} else if _, err := exec.LookPath("wl-copy"); err == nil {
				cmd = exec.Command("wl-copy")
			}
			if cmd != nil {
				cmd.Stdin = strings.NewReader(currentText)
				cmd.Run()
			}
		}
	}
}

// CollectMatches collects matches for TUI mode instead of printing them
type MatchCollector struct {
	Matches []Match
}

func NewMatchCollector() *MatchCollector {
	return &MatchCollector{
		Matches: make([]Match, 0),
	}
}

func (mc *MatchCollector) Add(file string, decoders []string, match, context string, offset int) {
	mc.Matches = append(mc.Matches, Match{
		File:     file,
		Decoders: decoders,
		Match:    match,
		Context:  context,
		Offset:   offset,
	})
}
