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
	pa, err := pfrouteScriptNamed("pfroute-android.sh")
	if err != nil {
		t.Fatalf("pfrouteScriptNamed(android): %v", err)
	}
	if pa == p {
		t.Fatalf("android path == darwin path (%s), 提取逻辑有误", pa)
	}
	sa, err := os.Stat(pa)
	if err != nil {
		t.Fatalf("stat %s: %v", pa, err)
	}
	if sa.Mode().Perm() != 0o755 {
		t.Fatalf("android mode = %v, want 0755", sa.Mode().Perm())
	}
	da, err := os.ReadFile(pa)
	if err != nil {
		t.Fatalf("read %s: %v", pa, err)
	}
	if !strings.HasPrefix(string(da), "#!/bin/sh") {
		t.Fatalf("pfroute-android.sh 必须以 #!/bin/sh 开头 (Android 没有 /bin/bash)")
	}
}
