# Metadata CNI IPAM

`metadata-cni-ipam` is a Linux CNI IPAM plugin that resolves a container's control-plane-assigned primary address from the platform metadata service.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/rancher-cni-ipam`](https://github.com/rancher/rancher-cni-ipam). This GitHub fork retains the upstream Git history, authorship, dates, and license notices unchanged; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

The current public compatibility release is `v0.2.7`. This repository does
not publish a mutable `latest` tag; future releases must use an unused pure
numeric version.

## POC scope

- CNI versions 0.1.0 through 1.1.0;
- lookup by runtime container ID with a platform UUID fallback;
- bounded polling through the 2015-12-19 metadata `containers` resource;
- configurable subnet prefix, routes, timeout, interval, and metadata endpoint;
- 8 MiB metadata response limit and optional HTTPS CA bundle;
- metadata requests bypass ambient proxies and do not follow redirects;
- the optional CA bundle is a regular file of at most 1 MiB at the managed
  read-only path `/var/lib/pasturestack/etc/ssl/ca.crt`;
- file logging is limited to `/var/log/pasturestack` and the deployed
  `/var/log/pasturestack-cni.log` compatibility path.

The plugin has no user interface or language catalog, so localization is not applicable.

## Build and test

```sh
go test -race ./...
go vet ./...
go mod verify
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/metadata-cni-ipam .
```

## Configuration

```json
{
  "cniVersion": "1.1.0",
  "name": "pasture-network",
  "ipam": {
    "type": "metadata-cni-ipam",
    "metadataURL": "http://metadata/2015-12-19",
    "subnetPrefixSize": "/16",
    "lookupTimeout": "2m",
    "pollInterval": "500ms"
  }
}
```

`PLATFORM_METADATA_URL` overrides `metadataURL`. To enable a private metadata
CA, set `PLATFORM_CA_ROOT` to the exact managed mount
`/var/lib/pasturestack/etc/ssl/ca.crt`; arbitrary paths, symbolic links,
non-regular files, and bundles larger than 1 MiB are rejected. `CNI_ARGS` may
supply `PlatformContainerUUID` as a fallback identifier.

## License and provenance

The root license remains unchanged. Existing history and attribution are retained; see [ORIGIN.md](ORIGIN.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [LICENSE](LICENSE).
