package metadata

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFinderRejectsArbitraryCARootPaths(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()

	caRootPath := filepath.Join(t.TempDir(), "ca.crt")
	caRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caRootPath, caRootPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewIPFinderFromMetadata(server.URL, caRootPath, time.Millisecond); err == nil || !strings.Contains(err.Error(), "must use") {
		t.Fatalf("expected arbitrary CA root path to fail before file access, got %v", err)
	}
}

func TestFinderUsesManagedCAContentForTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/containers" {
			http.NotFound(response, request)
			return
		}
		_, _ = response.Write([]byte(`[{"external_id":"runtime-tls","primary_ip":"192.0.2.44"}]`))
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	caRootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	finder, err := newIPFinderFromMetadata(parsed, caRootPEM, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	address, err := finder.FindIP(context.Background(), "runtime-tls", "")
	if err != nil {
		t.Fatal(err)
	}
	if address.String() != "192.0.2.44" {
		t.Fatalf("address = %s", address)
	}
}

func TestManagedCARootReaderEnforcesFileBoundary(t *testing.T) {
	t.Run("regular bounded file", func(t *testing.T) {
		directory := t.TempDir()
		content := []byte("managed CA content")
		if err := os.WriteFile(filepath.Join(directory, metadataCARootName), content, 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		got, err := readRegularBoundedFile(root, metadataCARootName, int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(content) {
			t.Fatalf("content = %q", got)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "target.crt"), []byte("target"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("target.crt", filepath.Join(directory, metadataCARootName)); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := readRegularBoundedFile(root, metadataCARootName, maxCARootBytes); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("expected symbolic link to fail, got %v", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Mkdir(filepath.Join(directory, metadataCARootName), 0o700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := readRegularBoundedFile(root, metadataCARootName, maxCARootBytes); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("expected directory to fail, got %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, metadataCARootName), []byte(strings.Repeat("x", 17)), 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		if _, err := readRegularBoundedFile(root, metadataCARootName, 16); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("expected oversized file to fail, got %v", err)
		}
	})
}

func TestFinderRejectsRedirectAndDisablesAmbientProxy(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	finder, err := NewIPFinderFromMetadata(redirector.URL, "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := finder.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("metadata client must bypass ambient proxies")
	}
	if _, err := finder.FindIP(context.Background(), "runtime-a", ""); err == nil {
		t.Fatal("expected redirect response to fail")
	}
	if redirected.Load() {
		t.Fatal("metadata client followed a redirect")
	}
}

func TestManagedCARootContractIsStable(t *testing.T) {
	if metadataCARootPath != "/var/lib/pasturestack/etc/ssl/ca.crt" {
		t.Fatalf("managed CA root path changed to %q", metadataCARootPath)
	}
}

func TestFinderRejectsInvalidConfiguration(t *testing.T) {
	for _, rawURL := range []string{
		"metadata/2015-12-19",
		"file:///2015-12-19",
		"ftp://metadata/2015-12-19",
		"http://user:pass@metadata/2015-12-19",
		"http://metadata/2015-12-19?token=value",
		"http://metadata/2015-12-19#fragment",
	} {
		if _, err := NewIPFinderFromMetadata(rawURL, "", time.Millisecond); err == nil {
			t.Fatalf("expected invalid metadata URL %q to fail", rawURL)
		}
	}
	parsed, err := url.Parse("https://metadata/2015-12-19")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newIPFinderFromMetadata(parsed, []byte("not a certificate"), time.Millisecond); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("expected invalid CA content to fail, got %v", err)
	}
}

func TestManagedCARootReaderRejectsInvalidState(t *testing.T) {
	if _, err := readRegularBoundedFile(nil, metadataCARootName, maxCARootBytes); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected nil root to fail, got %v", err)
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := readRegularBoundedFile(root, "missing.crt", maxCARootBytes); err == nil || !strings.Contains(err.Error(), "inspect") {
		t.Fatalf("expected missing file to fail, got %v", err)
	}
	if _, err := readRegularBoundedFile(root, metadataCARootName, 0); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected invalid size limit to fail, got %v", err)
	}
}

func TestFinderPollsAndMatchesBothIdentifiers(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/2015-12-19/containers" {
			http.NotFound(response, request)
			return
		}
		if calls.Add(1) == 1 {
			_, _ = response.Write([]byte(`[]`))
			return
		}
		_, _ = response.Write([]byte(`[{"external_id":"runtime-a","uuid":"platform-a","primary_ip":"192.0.2.25"}]`))
	}))
	defer server.Close()

	finder, err := NewIPFinderFromMetadata(server.URL+"/2015-12-19", "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	address, err := finder.FindIP(ctx, "missing", "platform-a")
	if err != nil {
		t.Fatal(err)
	}
	if got := address.String(); got != "192.0.2.25" {
		t.Fatalf("address = %s", got)
	}
}

func TestFinderRejectsInvalidAndOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[{"external_id":"runtime-a","primary_ip":"not-an-address"}]`))
	}))
	defer server.Close()
	finder, err := NewIPFinderFromMetadata(server.URL, "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.FindIP(context.Background(), "runtime-a", ""); err == nil {
		t.Fatal("expected invalid address to fail")
	}

	large := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[]` + strings.Repeat(" ", maxResponseBytes)))
	}))
	defer large.Close()
	finder, err = NewIPFinderFromMetadata(large.URL, "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finder.FindIP(context.Background(), "runtime-a", ""); err == nil {
		t.Fatal("expected oversized response to fail")
	}
}

func TestFinderTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	finder, err := NewIPFinderFromMetadata(server.URL, "", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := finder.FindIP(ctx, "runtime-a", ""); err == nil {
		t.Fatal("expected lookup timeout")
	}
}
