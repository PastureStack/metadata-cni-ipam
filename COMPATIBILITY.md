# Compatibility

The POC preserves the historical default IPv4 prefix of `/16`, route output, two-minute lookup window, and runtime-ID-first lookup. It adds bounded configuration, IPv6 default `/64`, current CNI result conversion, and a neutral platform UUID fallback.

Downstream templates must switch the executable and IPAM type to `metadata-cni-ipam`, use `PLATFORM_METADATA_URL`, and rename the CNI argument to `PlatformContainerUUID`. The data-plane packaging repository and flat IPAM import must be updated in the same compatibility wave.
