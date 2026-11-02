// Package wg wraps the wireguard-tools CLI and parses its output.
package wg

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner executes wg / wg-quick commands.
type Runner struct {
	WGBin    string
	QuickBin string
	ConfDir  string
	Timeout  time.Duration
}

func NewRunner(wgBin, quickBin string, confDir ...string) *Runner {
	dir := "/etc/wireguard"
	if len(confDir) > 0 && confDir[0] != "" {
		dir = confDir[0]
	}
	return &Runner{WGBin: wgBin, QuickBin: quickBin, ConfDir: dir, Timeout: 15 * time.Second}
}

func (r *Runner) run(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s %s: %s", bin, strings.Join(args, " "), msg)
	}
	return out.String(), nil
}
