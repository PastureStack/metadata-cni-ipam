package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestCNIHandlersWithMetadataFixture(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/2015-12-19/containers" {
			http.NotFound(response, request)
			return
		}
		_, _ = response.Write([]byte(`[{"external_id":"runtime-smoke","uuid":"platform-smoke","primary_ip":"192.0.2.25"}]`))
	}))
	defer server.Close()
	t.Setenv("PLATFORM_METADATA_URL", server.URL+"/2015-12-19")

	config := []byte(`{"cniVersion":"1.1.0","name":"metadata-smoke","ipam":{"type":"metadata-cni-ipam","subnetPrefixSize":"/24","lookupTimeout":"1s","pollInterval":"10ms"}}`)
	args := &skel.CmdArgs{
		ContainerID: "runtime-smoke",
		Args:        "PlatformContainerUUID=platform-smoke",
		StdinData:   config,
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writer
	err = cmdAdd(args)
	_ = writer.Close()
	os.Stdout = originalStdout
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	var result struct {
		IPs []struct {
			Address string `json:"address"`
		} `json:"ips"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode CNI result %q: %v", output, err)
	}
	if len(result.IPs) != 1 || result.IPs[0].Address != "192.0.2.25/24" {
		t.Fatalf("CNI result = %s", output)
	}
	if err := cmdCheck(args); err != nil {
		t.Fatal(err)
	}
	if err := cmdDel(args); err != nil {
		t.Fatal(err)
	}
}

func TestCommandLoggerUsesStandardErrorByDefault(t *testing.T) {
	logger, closeLog, err := commandLogger(&IPAMConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeLog()
	if logger.Writer() != os.Stderr {
		t.Fatal("default logger must use standard error")
	}
}

func TestCommandLogBoundary(t *testing.T) {
	t.Run("regular managed file", func(t *testing.T) {
		root := t.TempDir()
		file, err := openCommandLogFromRoot(root, "metadata.log")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString("line\n"); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(root, "metadata.log"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("log mode = %o", info.Mode().Perm())
		}
	})

	t.Run("traversal", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(filepath.Dir(root), "outside.log")
		if _, err := openCommandLogFromRoot(root, outside); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Fatalf("expected traversal to fail, got %v", err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.log")
		if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "metadata.log")); err != nil {
			t.Fatal(err)
		}
		if _, err := openCommandLogFromRoot(root, "metadata.log"); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("expected symbolic link to fail, got %v", err)
		}
		content, err := os.ReadFile(outside)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "preserve" {
			t.Fatalf("outside file changed to %q", content)
		}
	})
}

func TestCommandLogContractIsStable(t *testing.T) {
	if cniLogRoot != "/var/log/pasturestack" {
		t.Fatalf("managed log root changed to %q", cniLogRoot)
	}
	if deployedLogPath != "/var/log/pasturestack-cni.log" {
		t.Fatalf("deployed log path changed to %q", deployedLogPath)
	}
}
