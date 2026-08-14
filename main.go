package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PastureStack/metadata-cni-ipam/ipfinder"
	platformmetadata "github.com/PastureStack/metadata-cni-ipam/ipfinder/metadata"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

const defaultMetadataURL = "http://metadata/2015-12-19"

const (
	cniLogRoot      = "/var/log/pasturestack"
	deployedLogPath = "/var/log/pasturestack-cni.log"
)

var buildVersion = "dev"

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "PastureStack metadata CNI IPAM "+buildVersion)
}

func cmdAdd(args *skel.CmdArgs) error {
	config, configVersion, lookupTimeout, pollInterval, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	logger, closeLog, err := commandLogger(config)
	if err != nil {
		return err
	}
	defer closeLog()
	address, err := findAddress(config, lookupTimeout, pollInterval, args.ContainerID)
	if err != nil {
		return err
	}
	if config.IsDebugLevel == "true" {
		logger.Print("metadata address resolved for CNI container")
	}
	allocation, err := resultAddress(address, config.SubnetPrefixSize)
	if err != nil {
		return err
	}
	result := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
		IPs:        []*current.IPConfig{{Address: allocation}},
		Routes:     config.Routes,
	}
	return types.PrintResult(result, configVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	config, _, lookupTimeout, pollInterval, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	_, err = findAddress(config, lookupTimeout, pollInterval, args.ContainerID)
	return err
}

func cmdDel(*skel.CmdArgs) error {
	return nil
}

func findAddress(config *IPAMConfig, timeout, interval time.Duration, containerID string) (net.IP, error) {
	finder, err := platformmetadata.NewIPFinderFromMetadata(metadataURL(config.MetadataURL), os.Getenv("PLATFORM_CA_ROOT"), interval)
	if err != nil {
		return nil, err
	}
	return findWithTimeout(finder, timeout, containerID, string(config.PlatformContainerUUID))
}

func findWithTimeout(finder ipfinder.IPFinder, timeout time.Duration, containerID, platformID string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return finder.FindIP(ctx, containerID, platformID)
}

func metadataURL(configured string) string {
	if value := strings.TrimSpace(os.Getenv("PLATFORM_METADATA_URL")); value != "" {
		return value
	}
	if value := strings.TrimSpace(configured); value != "" {
		return value
	}
	return defaultMetadataURL
}

func resultAddress(address net.IP, configuredPrefix string) (net.IPNet, error) {
	prefix := configuredPrefix
	if prefix == "" {
		if address.To4() != nil {
			prefix = "/16"
		} else {
			prefix = "/64"
		}
	}
	if !strings.HasPrefix(prefix, "/") {
		return net.IPNet{}, fmt.Errorf("subnetPrefixSize must begin with '/'")
	}
	parsedIP, network, err := net.ParseCIDR(address.String() + prefix)
	if err != nil {
		return net.IPNet{}, fmt.Errorf("invalid address prefix: %w", err)
	}
	return net.IPNet{IP: parsedIP, Mask: network.Mask}, nil
}

func commandLogger(config *IPAMConfig) (*log.Logger, func(), error) {
	var output io.Writer = os.Stderr
	closeLog := func() {}
	if config.LogToFile != "" {
		file, err := openApprovedCommandLog(config.LogToFile)
		if err != nil {
			return nil, nil, err
		}
		output = file
		closeLog = func() { _ = file.Close() }
	}
	return log.New(output, "metadata-cni-ipam: ", log.LstdFlags), closeLog, nil
}

func openApprovedCommandLog(requestedPath string) (*os.File, error) {
	cleaned := filepath.Clean(strings.TrimSpace(requestedPath))
	if cleaned == deployedLogPath {
		return openCommandLogFromRoot(filepath.Dir(deployedLogPath), deployedLogPath)
	}
	return openCommandLogFromRoot(cniLogRoot, requestedPath)
}

func openCommandLogFromRoot(rootPath, requestedPath string) (*os.File, error) {
	requestedPath = strings.TrimSpace(requestedPath)
	if requestedPath == "" || strings.ContainsRune(requestedPath, '\x00') {
		return nil, fmt.Errorf("CNI log path is empty or invalid")
	}
	rootPath = filepath.Clean(rootPath)
	relativePath := filepath.Clean(requestedPath)
	if filepath.IsAbs(relativePath) {
		var err error
		relativePath, err = filepath.Rel(rootPath, relativePath)
		if err != nil {
			return nil, fmt.Errorf("CNI log path is outside the managed log directory")
		}
	}
	if relativePath == "." || !filepath.IsLocal(relativePath) {
		return nil, fmt.Errorf("CNI log path is outside the managed log directory")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("open managed CNI log directory: %w", err)
	}
	defer root.Close()

	before, inspectErr := root.Lstat(relativePath)
	flags := os.O_WRONLY | os.O_APPEND
	if inspectErr == nil {
		if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return nil, fmt.Errorf("CNI log path must be a regular file")
		}
	} else if os.IsNotExist(inspectErr) {
		before = nil
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		return nil, fmt.Errorf("inspect CNI log file: %w", inspectErr)
	}
	file, err := root.OpenFile(relativePath, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open CNI log file: %w", err)
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || (before != nil && !os.SameFile(before, after)) {
		_ = file.Close()
		return nil, fmt.Errorf("CNI log file changed while opening")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("restrict CNI log file: %w", err)
	}
	return file, nil
}
