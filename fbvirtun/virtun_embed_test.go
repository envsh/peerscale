package fbvirtun

import (
	"os"
	"strings"
	"testing"
)

func TestPfrouteScriptExtraction(t *testing.T) {
	p, err := pfrouteScript()
	if err != nil {
		t.Fatalf("pfrouteScript: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", st.Mode().Perm())
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	if !strings.HasPrefix(string(data), "#!/bin/bash") {
		t.Fatalf("content does not start with #!/bin/bash")
	}
	if _, err := pfrouteFS.ReadFile("pfroute-android.sh"); err != nil {
		t.Fatalf("embedded pfroute-android.sh: %v", err)
	}
}
