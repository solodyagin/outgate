package controlstate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestGrantCommitBeforeLostResponseNeverRecoversSecret(t *testing.T) {
	if os.Getenv("OUTGATE_GRANT_CRASH_HELPER") == "1" {
		config := Config{Path: os.Getenv("OUTGATE_GRANT_CRASH_PATH"), Epoch: [32]byte{1}, Services: map[string][]string{"reports": {"/api"}}}
		s, err := Open(context.Background(), config)
		if err != nil {
			os.Exit(1)
		}
		var c Change
		var b GrantBinding
		if json.Unmarshal([]byte(os.Getenv("OUTGATE_GRANT_CHANGE")), &c) != nil || json.Unmarshal([]byte(os.Getenv("OUTGATE_GRANT_BINDING")), &b) != nil {
			os.Exit(2)
		}
		issued, err := s.IssueGrant(context.Background(), c, b)
		if err != nil || issued.DeploymentGrant == "" {
			os.Exit(3)
		}
		os.Exit(0) // committed, but no response or deferred database close
	}
	config := securityConfig(t)
	must(t, Initialize(t.Context(), config))
	c, b := change(t, 1), binding()
	cJSON, err := json.Marshal(c)
	must(t, err)
	bJSON, err := json.Marshal(b)
	must(t, err)
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestGrantCommitBeforeLostResponseNeverRecoversSecret$")
	child.Env = append(os.Environ(), "OUTGATE_GRANT_CRASH_HELPER=1", "OUTGATE_GRANT_CRASH_PATH="+config.Path, "OUTGATE_GRANT_CHANGE="+string(cJSON), "OUTGATE_GRANT_BINDING="+string(bJSON))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("lost-response helper failed: %v (%s)", err, output)
	}
	s, err := Open(t.Context(), config)
	must(t, err)
	defer s.Close()
	issued, err := s.IssueGrant(t.Context(), c, b)
	must(t, err)
	if issued.DeploymentGrant != "" || issued.Record.GrantID == "" {
		t.Fatal("restart replay recovered a credential")
	}
	events, err := s.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 1 || events[0].Target.Value != issued.Record.GrantID {
		t.Fatal("lost response was not committed atomically")
	}
	_, err = s.GrantForPeer(t.Context(), issued.Record.GrantID, peer())
	must(t, err)
}
