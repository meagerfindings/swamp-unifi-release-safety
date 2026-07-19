# Silent Mode Design

This model follows the **silent-by-default** pattern:

1. **No new CVEs** → `alertText` is empty string, `newCVEs` is empty array
2. **New CVEs found** → Full markdown alert with CVE details, severity scores, and references
3. **State persistence** → `unifi-cve-state.json` tracks all checked CVE IDs for cross-run dedup

## Why Silence Matters

Alert fatigue kills automation value. By only sounding when genuinely new
HIGH/CRITICAL CVEs are published, this model can run on aggressive schedules
(every 20 min, every hour) without flooding channels.

## Integration Pattern

Always guard the consumer model with a CEL expression:

```yaml
when: "data.latest(..., scan).attributes.alertText != ''"
```

This ensures downstream notify models only fire when there's actually
something to report.
