# Security

Do not report credentials, private metadata, container identifiers, or exploit details in public issues. Use the organization security-reporting channel once published.

Metadata responses are limited to 8 MiB, requests bypass ambient proxies,
redirects are rejected, and request and total lookup times are bounded. A
private metadata CA can only be read as a regular file of at most 1 MiB from
`/var/lib/pasturestack/etc/ssl/ca.crt`. Log files use mode `0600` and are
restricted to `/var/log/pasturestack` plus the deployed
`/var/log/pasturestack-cni.log` compatibility path. Privileged runtime, CA
rotation, metadata outage, upgrade, and rollback testing remain downstream
integration gates.
