# @mgreten/unifi-release-safety

Read-only UniFi firmware release monitoring and safety-review scheduling for
Swamp. It never installs firmware, never changes Home Assistant/UniFi
configuration, and never makes a network request except the optional
Home Assistant states read.

Two independent collection modes feed the same deduplication and review
pipeline, so you can use either one alone or both together on the same model
instance:

- **Home Assistant mode** (`scan`) — reads an explicit list of Home
  Assistant firmware `update.*` entities.
- **Direct-observation mode** (`observe`) — accepts model/installed-version/
  target-version observations supplied directly by the caller. No Home
  Assistant instance, controller URL, or credentials required.

## What it does

- Detects newly offered UniFi firmware (an installed-to-target version
  transition) from either source.
- Deduplicates each transition by a stable key so the same offered version is
  never re-reported for the same device/model.
- Schedules a research checkpoint when a transition is first seen, then again
  at 7, 14, and 21 days if it is still current — so early "this bricked my
  device" reports have time to surface before you act.
- Stores all observation state as a Swamp `releaseSafetyReport` resource,
  not a local file, database, or cron job.
- Never installs firmware, never sends notifications itself, and never
  asserts that any update is safe — it only tells you when a human (or
  agent) research pass is due.

## Global arguments

All fields are optional at the model level; only `scan` requires the Home
Assistant fields to be set. `observe` needs none of them.

| Argument | Type | Required for | Description |
| --- | --- | --- | --- |
| `homeAssistantUrl` | `string` (URL) | `scan` | Home Assistant base URL |
| `homeAssistantToken` | `string` (sensitive) | `scan` | Read-only Home Assistant long-lived access token |
| `entityIds` | `string[]` | `scan` | Explicit Home Assistant firmware-update entity IDs to monitor |

```bash
swamp model create @mgreten/unifi-release-safety unifi-release-safety
```

Configure `homeAssistantUrl`, `homeAssistantToken`, and `entityIds` on the
private model instance (e.g. via vault-backed CEL expressions) only if you
intend to use `scan`. Skip them entirely for direct-observation-only use.

## Home Assistant mode: `scan`

Reads the configured Home Assistant firmware-update entities, keeps only the
ones in `entityIds`, and reports newly offered versions plus anything due for
its next review checkpoint. Requires `homeAssistantUrl`, `homeAssistantToken`,
and at least one `entityIds` entry to be set on the model instance; throws a
clear error if any are missing. Makes exactly one HTTP `GET` request to
`{homeAssistantUrl}/api/states`.

```bash
swamp model method run unifi-release-safety scan --json
```

No arguments are accepted by `scan` — everything it needs comes from the
global model configuration.

## Direct-observation mode: `observe`

Use `observe` when an agent, inventory script, release feed, or a person
already knows the installed and offered firmware versions for a device.
Home Assistant, a controller URL, and credentials are not required, and
`observe` makes no network request at all.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `model` | `string` | yes | Device hardware/software model identifier |
| `installedVersion` | `string` | yes | Currently installed firmware version |
| `targetVersion` | `string` | yes | Offered/available target firmware version |
| `deviceId` | `string` | no | Caller-defined identifier; used for dedup instead of `model` when present |
| `releaseUrl` | `string` (URL) | no | Link to release notes/changelog for the target version |

```bash
swamp model method run unifi-release-safety observe --json \
  --input 'observations:json=[
    {
      "model": "USW-Example-24-PoE",
      "installedVersion": "1.2.3",
      "targetVersion": "2.0.0",
      "deviceId": "example-switch-a",
      "releaseUrl": "https://example.com/releases/2.0.0"
    },
    {
      "model": "UAP-Example-AC",
      "installedVersion": "6.1.61",
      "targetVersion": "6.2.10"
    }
  ]'
```

`model`, `installedVersion`, and `targetVersion` are required for every
entry; `installedVersion` equal to `targetVersion` is treated as "nothing
offered" and skipped. `deviceId` is optional — when present it becomes the
dedup identity instead of `model`, so you can track two devices of the same
model independently. Omitting it deduplicates by model + version transition
only.

## Dedup key and review scheduling (shared by both modes)

Both modes write into the same `releaseSafetyReport` resource and use the
same logic:

- **Dedup key**: `scan` keys each transition as
  `{entityId}:{installedVersion}->{targetVersion}`. `observe` keys each
  transition as `direct:{deviceId or model}:{installedVersion}->{targetVersion}`.
  A transition already tracked keeps its original `firstSeenAt` and review
  history across repeated calls; only its `lastSeenAt` is refreshed.
- **Review checkpoints**: `initial` (as soon as first seen), then `day7`,
  `day14`, and `day21`, each measured from `firstSeenAt`. A transition
  appears in `reviewCandidates` only when its next checkpoint is due.
- Running `scan` only ever re-evaluates Home Assistant-sourced entries, and
  running `observe` only ever re-evaluates direct-observation entries — using
  one mode never marks the other mode's tracked transitions as stale.

After a candidate is researched and delivered, call `acknowledge` with its
`key` and the `stage` you delivered. That advances only that transition to
its next checkpoint (or clears it after `day21`), preventing duplicate
notifications for the same stage.

```bash
swamp model method run unifi-release-safety acknowledge --json \
  --input 'acknowledgements:json=[{"key":"direct:example-switch-a:1.2.3->2.0.0","stage":"initial"}]'
```

## Reading results

```bash
swamp data get unifi-release-safety release-safety-current --json
```

The resource holds `availableUpdates` (everything currently tracked, from
both sources), `reviewCandidates` (what is due for research right now from
whichever mode you just ran), and `staleReleaseKeys` (transitions from the
mode you just ran that are no longer being offered — not evidence they were
installed, withdrawn, or made safe).

## Operational use

Run `scan`, `observe`, or both on whatever cadence fits your environment,
then research and deliver only the returned `reviewCandidates`. Treat
official vendor release notes as the primary source and public community
reports as evidence to weigh, not automatic proof a version is unsafe. Once
delivered, call `acknowledge` so the same stage is not repeated.

## Privacy and safety

- All methods are read-only; nothing here installs firmware or changes
  device/controller/Home Assistant configuration.
- `observe` needs no credentials or private infrastructure access at all.
- Home Assistant configuration (`homeAssistantUrl`, `homeAssistantToken`,
  `entityIds`) is optional, sensitive runtime input — keep it on the private
  model instance, never in extension source, examples, or documentation.
- All examples in this document use synthetic model names, versions, URLs,
  and identifiers.
- Do not place raw Home Assistant state payloads, credentials, private
  hosts/IPs, device names, or location data in public inputs, examples, or
  documentation.
