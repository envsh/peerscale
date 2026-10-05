package fbvirtun

import (
	"embed"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
)

//go:embed pfroute-darwin.sh pfroute-android.sh
var pfrouteFS embed.FS

var (
	pfrouteOnce    sync.Once
	pfrouteDarwin  string
	pfrouteAndroid string
	pfrouteErr     error
)

// pfrouteScript returns the extracted path of pfroute-darwin.sh.
func pfrouteScript() (string, error) {
	p, _, err := pfrouteScripts()
	return p, err
}

// pfrouteScriptNamed returns the extracted path of one of the embedded scripts.
// Extraction is lazy and cached.
func pfrouteScriptNamed(name string) (string, error) {
	d, a, err := pfrouteScripts()
	if err != nil {
		return "", err
	}
	if name == "pfroute-android.sh" {
		return a, nil
	}
	return d, nil
}

func pfrouteScripts() (darwin, android string, err error) {
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
				if rmErr := os.RemoveAll(dir); rmErr != nil {
					log.Printf("pfroute: RemoveAll(%s) FAIL: %v", dir, rmErr)
				}
				return
			}
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
				pfrouteErr = err
				if rmErr := os.RemoveAll(dir); rmErr != nil {
					log.Printf("pfroute: RemoveAll(%s) FAIL: %v", dir, rmErr)
				}
				return
			}
		}
		pfrouteDarwin = filepath.Join(dir, "pfroute-darwin.sh")
		pfrouteAndroid = filepath.Join(dir, "pfroute-android.sh")
	})
	return pfrouteDarwin, pfrouteAndroid, pfrouteErr
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
			log.Printf("pfroute: 候选目录 MkdirAll(%s) FAIL: %v", c, err)
			continue
		}
		probe := filepath.Join(c, ".pfroute-probe")
		f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			log.Printf("pfroute: 探测文件 OpenFile(%s) FAIL: %v", probe, err)
			continue
		}
		if err := f.Close(); err != nil {
			log.Printf("pfroute: 探测文件 Close(%s) FAIL: %v", probe, err)
		}
		if err := os.Remove(probe); err != nil {
			log.Printf("pfroute: 探测文件 Remove(%s) FAIL: %v", probe, err)
		}
		return c, nil
	}
	return "", errors.New("no writable temp directory found")
}
