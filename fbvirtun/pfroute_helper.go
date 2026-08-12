package fbvirtun

import (
	"embed"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

//go:embed pfroute-darwin.sh pfroute-android.sh
var pfrouteFS embed.FS

var (
	pfrouteOnce sync.Once
	pfroutePath string
	pfrouteErr  error
)

// pfrouteScript returns the extracted path of pfroute-darwin.sh. pfroute-android.sh
// is embedded for completeness but never executed. Extraction is lazy and cached.
func pfrouteScript() (string, error) {
	pfrouteOnce.Do(func() {
		dir, err := writableTempDir()
		if err != nil {
			pfrouteErr = err
			return
		}
		for _, name := range []string{"pfroute-darwin.sh", "pfroute-android.sh"} {
			data, err := pfrouteFS.ReadFile(name)
			if err != nil {
				pfrouteErr = err
				os.RemoveAll(dir)
				return
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
				pfrouteErr = err
				os.RemoveAll(dir)
				return
			}
		}
		pfroutePath = filepath.Join(dir, "pfroute-darwin.sh")
	})
	return pfroutePath, pfrouteErr
}

// writableTempDir returns the first candidate in which a probe file can be
// created, in order: os.TempDir(), /tmp, $HOME/.cache/libp2px, $HOME, the
// executable's directory, then ".".
func writableTempDir() (string, error) {
	var cands []string
	if t := os.TempDir(); t != "" {
		cands = append(cands, t)
	}
	cands = append(cands, "/tmp")
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		cands = append(cands, filepath.Join(h, ".cache", "libp2px"))
		cands = append(cands, h)
	}
	if exe, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Dir(exe))
	}
	cands = append(cands, ".")
	for _, c := range cands {
		if err := os.MkdirAll(c, 0o755); err != nil {
			continue
		}
		probe := filepath.Join(c, ".pfroute-probe")
		f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			continue
		}
		f.Close()
		os.Remove(probe)
		return c, nil
	}
	return "", errors.New("no writable temp directory found")
}
