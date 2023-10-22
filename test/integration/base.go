package integration

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func RunCmd(t testing.TB, cmd []string) (*exec.Cmd, string, error) {
	HEAD := cmd[0]
	CMD := cmd[1:]
	execCmd := exec.Command(HEAD, CMD...)
	execCmd.Env = os.Environ()

	out, err := execCmd.CombinedOutput()
	if err != nil {
		t.Logf("[COMMAND] exec fail, Command: %v", cmd)
	} else {
		t.Logf("[COMMAND] exec success, Command: %v", cmd)
	}
	return execCmd, string(out), err
}

func runCmd(t testing.TB, args ...string) (*exec.Cmd, string, error) {
	binaryLocation := path.Join(repoRoot(t), ".tmp", "valint")
	cmd_list := []string{binaryLocation}
	cmd_list = append(cmd_list, args...)
	return RunCmd(t, cmd_list)
}

func repoRoot(t testing.TB) string {
	t.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		t.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}
