package metadata

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxResponseBytes = 8 << 20

const (
	metadataCARootDirectory = "/var/lib/pasturestack/etc/ssl"
	metadataCARootName      = "ca.crt"
	metadataCARootPath      = metadataCARootDirectory + "/" + metadataCARootName
	maxCARootBytes          = 1 << 20
)

type Container struct {
	ExternalID string `json:"external_id"`
	UUID       string `json:"uuid"`
	PrimaryIP  string `json:"primary_ip"`
}

type IPFinderFromMetadata struct {
	endpoint     string
	client       *http.Client
	pollInterval time.Duration
}

func NewIPFinderFromMetadata(rawURL, caRootPath string, pollInterval time.Duration) (*IPFinderFromMetadata, error) {
	parsed, err := url.Parse(strings.TrimRight(rawURL, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid metadata URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("metadata URL must not contain credentials, query, or fragment")
	}
	var caRootPEM []byte
	if caRootPath != "" {
		caRootPEM, err = readApprovedMetadataCARoot(caRootPath)
		if err != nil {
			return nil, err
		}
	}
	return newIPFinderFromMetadata(parsed, caRootPEM, pollInterval)
}

func newIPFinderFromMetadata(parsed *url.URL, caRootPEM []byte, pollInterval time.Duration) (*IPFinderFromMetadata, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caRootPEM) != 0 {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caRootPEM) {
			return nil, fmt.Errorf("metadata CA root contains no certificates")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &IPFinderFromMetadata{
		endpoint:     parsed.String() + "/containers",
		pollInterval: pollInterval,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func readApprovedMetadataCARoot(requestedPath string) ([]byte, error) {
	if requestedPath != metadataCARootPath {
		return nil, fmt.Errorf("metadata CA root must use %s", metadataCARootPath)
	}
	root, err := os.OpenRoot(metadataCARootDirectory)
	if err != nil {
		return nil, fmt.Errorf("open metadata CA root directory: %w", err)
	}
	defer root.Close()
	return readRegularBoundedFile(root, metadataCARootName, maxCARootBytes)
}

func readRegularBoundedFile(root *os.Root, name string, maximumBytes int64) ([]byte, error) {
	if root == nil || name == "" || maximumBytes < 1 {
		return nil, fmt.Errorf("metadata CA root reader is not configured")
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect metadata CA root: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("metadata CA root must be a regular file")
	}
	if before.Size() > maximumBytes {
		return nil, fmt.Errorf("metadata CA root exceeds %d bytes", maximumBytes)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open metadata CA root: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened metadata CA root: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("metadata CA root changed while opening")
	}
	pem, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read metadata CA root: %w", err)
	}
	if int64(len(pem)) > maximumBytes {
		return nil, fmt.Errorf("metadata CA root exceeds %d bytes", maximumBytes)
	}
	return pem, nil
}

func (finder *IPFinderFromMetadata) FindIP(ctx context.Context, containerID, platformID string) (net.IP, error) {
	ticker := time.NewTicker(finder.pollInterval)
	defer ticker.Stop()
	for {
		containers, err := finder.containers(ctx)
		if err != nil {
			return nil, err
		}
		for _, container := range containers {
			if container.ExternalID != containerID && (platformID == "" || container.UUID != platformID) {
				continue
			}
			address := net.ParseIP(container.PrimaryIP)
			if address == nil {
				return nil, fmt.Errorf("metadata returned an invalid primary IP")
			}
			return address, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("metadata IP lookup timed out: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (finder *IPFinderFromMetadata) containers(ctx context.Context) ([]Container, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, finder.endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := finder.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("metadata containers returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("metadata containers response exceeds %d bytes", maxResponseBytes)
	}
	var containers []Container
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("decode metadata containers: %w", err)
	}
	return containers, nil
}
