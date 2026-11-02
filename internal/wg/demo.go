package wg

import (
	"fmt"
	"strings"
	"time"
)

// DemoRunner fakes every operation so the UI can be developed without
// root privileges or the wg binary (e.g. on macOS).
type DemoRunner struct {
	Runner
}

func NewDemoRunner() *DemoRunner { return &DemoRunner{Runner: *NewRunner("wg", "wg-quick")} }

var _ Backend = (*DemoRunner)(nil)

func (d *DemoRunner) ShowAllDump() (string, error) {
	now := time.Now().Unix()
	lines := []string{
		"wg0\t" + demoPriv1 + "\t" + demoPub1 + "\t51820\toff",
		"wg0\t" + demoPeerPub1 + "\toff\t203.0.113.7:41234\t10.10.0.2/32,fd00::2/128\t" +
			fmt.Sprintf("%d", now-42) + "\t104857600\t524288000\t25",
		"wg0\t" + demoPeerPub2 + "\t" + demoPSK + "\t(none)\t10.10.0.3/32\t0\t0\t0\toff",
		"wg0\t" + demoPeerPub3 + "\toff\t198.51.100.9:51820\t10.10.0.4/32\t" +
			fmt.Sprintf("%d", now-3600) + "\t4096\t8192\toff",
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func (d *DemoRunner) SetPeerRemove(iface, publicKey string) error { return nil }
func (d *DemoRunner) QuickUp(iface string) error                  { return nil }
func (d *DemoRunner) QuickDown(iface string) error                { return nil }
func (d *DemoRunner) SyncConf(iface string) error                 { return nil }

var (
	demoPriv1    = "6GqBlRlvVKtrVXn6Fm3HvafCV8kCL0R4ufKuNvTcn3o="
	demoPub1     = "kiIeVuaa7V4+fFdx8gh+m1lZHc0Bfsj4pPsLSD8oOjg="
	demoPeerPub1 = "qZ1zFfO0YrTHSaCOdSSTLGgTlIw4CjBTQ5mjuKxkzTM="
	demoPeerPub2 = "Wb1l0n8QeB4sJ7FjrbOtOFPLIBo3rSCmRFy9vFbcRTA="
	demoPeerPub3 = "Lp2XUUzCvzuPQhKnWm6i3q0lTtH0sJ1cE9DkGvAaRxM="
	demoPSK      = "9lRfF4aS0DpVj7TQmXcZ2bYhUoN1eKwLrP5gJ8vCxHs="
)
