package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/containernetworking/cni/pkg/types"
)

const (
	defaultLookupTimeout = 2 * time.Minute
	defaultPollInterval  = 500 * time.Millisecond
)

type IPAMConfig struct {
	types.CommonArgs
	Type                  string                     `json:"type"`
	LogToFile             string                     `json:"logToFile"`
	IsDebugLevel          string                     `json:"isDebugLevel"`
	SubnetPrefixSize      string                     `json:"subnetPrefixSize"`
	Routes                []*types.Route             `json:"routes"`
	MetadataURL           string                     `json:"metadataURL"`
	LookupTimeout         string                     `json:"lookupTimeout"`
	PollInterval          string                     `json:"pollInterval"`
	PlatformContainerUUID types.UnmarshallableString `json:"platformContainerUUID,omitempty"`
}

type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`
}

func LoadIPAMConfig(data []byte, args string) (*IPAMConfig, string, time.Duration, time.Duration, error) {
	network := Net{}
	if err := json.Unmarshal(data, &network); err != nil {
		return nil, "", 0, 0, fmt.Errorf("load network config: %w", err)
	}
	if network.IPAM == nil {
		return nil, "", 0, 0, fmt.Errorf("IPAM config missing 'ipam' key")
	}
	if network.Name == "" {
		return nil, "", 0, 0, fmt.Errorf("network config missing 'name'")
	}
	if args != "" {
		if err := types.LoadArgs(args, network.IPAM); err != nil {
			return nil, "", 0, 0, fmt.Errorf("parse CNI args: %w", err)
		}
	}
	if network.CNIVersion == "" {
		network.CNIVersion = "0.1.0"
	}
	lookupTimeout, err := parseDuration(network.IPAM.LookupTimeout, defaultLookupTimeout, "lookupTimeout")
	if err != nil {
		return nil, "", 0, 0, err
	}
	pollInterval, err := parseDuration(network.IPAM.PollInterval, defaultPollInterval, "pollInterval")
	if err != nil {
		return nil, "", 0, 0, err
	}
	if pollInterval > lookupTimeout {
		return nil, "", 0, 0, fmt.Errorf("pollInterval must not exceed lookupTimeout")
	}
	return network.IPAM, network.CNIVersion, lookupTimeout, pollInterval, nil
}

func parseDuration(value string, fallback time.Duration, name string) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid %s", name)
	}
	return duration, nil
}
