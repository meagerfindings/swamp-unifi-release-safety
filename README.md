# UniFi Release Safety

A public Swamp extension containing `@mgreten/unifi-cve-watcher`: a silent-by-default watcher for newly published, high-severity UniFi/Ubiquiti security advisories and CVEs.

## What it checks

The model checks these sources, in order of authority:

1. Official Ubiquiti Community Security Advisory Bulletins
2. NVD CVE API
3. GitHub Advisory Database

Official Ubiquiti bulletins are queried first because they can include the affected product and fixed-version details before an NVD or GitHub record is available.

## Alert behavior

The watcher only returns alert text for newly observed HIGH or CRITICAL findings. A routine scan with no new findings returns an empty `alertText` value, so downstream notifications can remain quiet.

It records observed IDs in `unifi-cve-state.json` in its runtime repository directory. That state file is intentionally ignored by Git.

## Model

### `@mgreten/unifi-cve-watcher.run`

Optional arguments:

- `keywords`: keyword list used for NVD and GitHub Advisory searches.
- `maxResults`: maximum records per source (default `20`; maximum `100`).
- `includeDetails`: compatibility flag for callers that want detailed finding fields.
- `currentProduct`: product name to evaluate against an official bulletin, such as `UDM-Pro`.
- `currentVersion`: installed version for `currentProduct`; the model reports whether the official bulletin indicates it is patched, affected, or unknown.

The result resource includes:

- `alertText`: Markdown-formatted alert, or an empty string when there is nothing new.
- `newCVEs`: newly observed finding records.
- `totalScanned`: number of in-scope HIGH/CRITICAL findings.
- `timestamp`: ISO 8601 scan time.

## Notification workflow pattern

Only notify when the model actually returns alert text:

```yaml
steps:
  - model: "@mgreten/unifi-cve-watcher"
    method: run
    args:
      currentProduct: "UDM-Pro"
      currentVersion: "4.0.21"

  - model: "@mgreten/ntfy-notify"
    method: post
    args:
      message: "{{ data.latest('@mgreten/unifi-cve-watcher', 'scan').attributes.alertText }}"
    when: "data.latest('@mgreten/unifi-cve-watcher', 'scan').attributes.alertText != ''"
```

## Development

This repository contains extension source only: no device credentials, local state, schedules, or notification targets are committed.

```bash
swamp extension fmt manifest.yaml --repo-dir .
swamp extension fmt manifest.yaml --repo-dir . --check
swamp extension quality manifest.yaml --repo-dir . --json
```

This GitHub repository is source control for the extension. Publishing a version to the Swamp registry is a separate, deliberate action.

## License

MIT. See [LICENSE.md](LICENSE.md).
