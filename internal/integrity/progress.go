// Copyright 2026 Bitwise Media Group Ltd.
// SPDX-License-Identifier: MIT

package integrity

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// steps renders a live checklist of verification steps. On a terminal each
// step appears as a bullet the moment it starts — the slow steps (asset
// download, Sigstore verification) would otherwise look like a hang — and the
// line is rewritten in place to a green check or red cross when it finishes.
// Off-terminal only the finished lines are printed, so piped output and CI
// logs stay clean. A nil writer discards everything.
type steps struct {
	out   io.Writer
	tty   bool
	color bool
	cur   string // step started but not yet finished
}

// newSteps builds the checklist writer; nil out silences it.
func newSteps(out io.Writer) *steps {
	if out == nil {
		return &steps{out: io.Discard}
	}
	s := &steps{out: out}
	if f, ok := out.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		s.tty = true
		s.color = os.Getenv("NO_COLOR") == ""
	}
	return s
}

// start begins a step, rendering it as an in-progress bullet on a terminal.
func (s *steps) start(msg string) {
	s.cur = msg
	if s.tty {
		_, _ = fmt.Fprintf(s.out, "• %s", msg)
	}
}

// done finishes the current step with a green check.
func (s *steps) done() { s.finish("✓", "32") }

// fail finishes the current step with a red cross.
func (s *steps) fail() { s.finish("✗", "31") }

// finish closes the started step, replacing the in-progress bullet on a
// terminal (carriage return + erase-line) or emitting the completed line
// off-terminal. Without a started step it is a no-op, so error paths may call
// fail unconditionally.
func (s *steps) finish(mark, colorCode string) {
	if s.cur == "" {
		return
	}
	if s.color {
		mark = "\033[" + colorCode + "m" + mark + "\033[0m"
	}
	if s.tty {
		_, _ = fmt.Fprintf(s.out, "\r\033[2K%s %s\n", mark, s.cur)
	} else {
		_, _ = fmt.Fprintf(s.out, "%s %s\n", mark, s.cur)
	}
	s.cur = ""
}

// info prints an indented explanatory line between steps.
func (s *steps) info(msg string) {
	_, _ = fmt.Fprintf(s.out, "  %s\n", msg)
}
