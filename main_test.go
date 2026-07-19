package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
