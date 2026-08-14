package main

import (
	"testing"
	"time"
)

func TestLoadIPAMConfig(t *testing.T) {
	data := []byte(`{"cniVersion":"1.1.0","name":"test","ipam":{"type":"metadata-cni-ipam","lookupTimeout":"3s","pollInterval":"20ms"}}`)
	config, cniVersion, timeout, interval, err := LoadIPAMConfig(data, "PlatformContainerUUID=platform-a")
	if err != nil {
		t.Fatal(err)
	}
	if cniVersion != "1.1.0" || timeout != 3*time.Second || interval != 20*time.Millisecond {
		t.Fatalf("version=%q timeout=%s interval=%s", cniVersion, timeout, interval)
	}
	if string(config.PlatformContainerUUID) != "platform-a" {
		t.Fatalf("platform ID = %q", config.PlatformContainerUUID)
	}
}

func TestLoadIPAMConfigRejectsInvalidInput(t *testing.T) {
	if _, _, _, _, err := LoadIPAMConfig([]byte(`{"name":"test"}`), ""); err == nil {
		t.Fatal("expected missing IPAM config to fail")
	}
	data := []byte(`{"name":"test","ipam":{"lookupTimeout":"1s","pollInterval":"2s"}}`)
	if _, _, _, _, err := LoadIPAMConfig(data, ""); err == nil {
		t.Fatal("expected poll interval longer than timeout to fail")
	}
}

func TestResultAddress(t *testing.T) {
	address, err := resultAddress([]byte{192, 0, 2, 25}, "/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "192.0.2.25/24" {
		t.Fatalf("address = %s", got)
	}
	if _, err := resultAddress([]byte{192, 0, 2, 25}, "24"); err == nil {
		t.Fatal("expected missing slash to fail")
	}
}
