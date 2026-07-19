/**
 * UniFi/Ubiquiti CVE watcher.
 *
 * Monitors official Ubiquiti Security Advisory Bulletins first, then augments
 * with NVD and GitHub Advisory DB. Official bulletins are authoritative because
 * they often appear before NVD/GitHub entries and include per-product fixed
 * version thresholds.
 *
 * @module
 */

import { z } from "npm:zod@4";

const DEFAULT_KEYWORDS = [
  "ubiquiti",
  "unifi",
  "dream machine",
  "udm",
  "udm pro",
];

const CHECK_ARGS = z.object({
  keywords: z.array(z.string()).optional(),
  maxResults: z.number().int().positive().max(100).optional().describe(
    "Max advisory/CVE records per source (default 20)",
  ),
  includeDetails: z.boolean().optional().describe(
    "Include CVE descriptions and references",
  ),
  currentProduct: z.string().optional().describe(
    "Product to evaluate, e.g. UDM-Pro",
  ),
  currentVersion: z.string().optional().describe(
    "Currently installed UniFi OS/app version for product-aware status",
  ),
});

const CVE_SCHEMA = z.object({
  cve_id: z.string(),
  description: z.string(),
  severity_score: z.number(),
  severity: z.enum(["HIGH", "CRITICAL"]),
  source: z.enum(["UBIQUITI", "NVD", "GITHUB"]),
  published: z.string(),
  bulletin: z.string().optional(),
  affectedProducts: z.string().optional(),
  mitigation: z.string().optional(),
  fixedVersion: z.string().optional(),
  currentProduct: z.string().optional(),
  currentVersion: z.string().optional(),
  currentStatus: z.enum(["patched", "affected", "unknown", "not_applicable"])
    .optional(),
  references: z.array(z.string()),
});

const CHECK_OUTPUT = z.object({
  alertText: z.string().describe(
    "Human-readable alert (empty string when nothing new)",
  ),
  newCVEs: z.array(CVE_SCHEMA).describe("New CVEs discovered this check"),
  totalScanned: z.number().describe("Total CVEs in scope for this run"),
  timestamp: z.string().describe("ISO timestamp of the check"),
});

type WatchState = {
  lastCheck: string | null;
  checkedCves: string[];
};

type Finding = z.infer<typeof CVE_SCHEMA>;

/** Fetch JSON with retry/backoff. */
async function fetchJson(url: string, opts?: RequestInit): Promise<unknown> {
  for (let i = 0; i < 2; i++) {
    try {
      const resp = await fetch(url, {
        ...opts,
        signal: AbortSignal.timeout(8_000),
      });
      if (!resp.ok) continue;
      return (await resp.json()) as unknown;
    } catch {
      await new Promise((r) => setTimeout(r, 2 ** i * 500));
    }
  }
  return null;
}

/** Load persisted state from local JSON, accepting old snake_case state too. */
async function loadState(repoDir: string): Promise<WatchState> {
  const statePath = `${repoDir}/unifi-cve-state.json`;
  try {
    const raw = await Deno.readTextFile(statePath);
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return {
      lastCheck: (parsed.lastCheck ?? parsed.last_check ?? null) as
        | string
        | null,
      checkedCves:
        (parsed.checkedCves ?? parsed.checked_cves ?? []) as string[],
    };
  } catch {
    return { lastCheck: null, checkedCves: [] };
  }
}

/** Save state for next-run deduplication. */
async function saveState(repoDir: string, data: WatchState): Promise<void> {
  await Deno.writeTextFile(
    `${repoDir}/unifi-cve-state.json`,
    JSON.stringify(
      {
        lastCheck: data.lastCheck,
        checkedCves: data.checkedCves,
        last_check: data.lastCheck,
        checked_cves: data.checkedCves,
      },
      null,
      2,
    ),
  );
}

/** Convert minimal HTML advisory content to readable text. */
function htmlToText(html: string): string {
  return html
    .replace(/<br\s*\/?\s*>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+\n/g, "\n")
    .replace(/\n\s+/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

/** Compare dotted version strings. Returns -1/0/1. */
function compareVersions(left: string, right: string): number {
  const a = left.split(/[.+-]/).map((part) => Number.parseInt(part, 10) || 0);
  const b = right.split(/[.+-]/).map((part) => Number.parseInt(part, 10) || 0);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff < 0) return -1;
    if (diff > 0) return 1;
  }
  return 0;
}

/** Return true when an ISO-ish publication date is within the last two years. */
function isRecentIso(dateText: string): boolean {
  if (!dateText) return false;
  const parsed = new Date(dateText);
  if (Number.isNaN(parsed.getTime())) return false;
  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - 2);
  return parsed >= cutoff;
}

/** Extract text after a label until the next major label. */
function extractLabeled(section: string, label: string): string {
  const re = new RegExp(
    `${label}:?\\s*([\\s\\S]*?)(?=Affected Products:?|Mitigation:?|Impact:?|CVSS|Base Score|Vector:?|CVE:?|Note:|$)`,
    "i",
  );
  return section.match(re)?.[1]?.replace(/\s+/g, " ").trim() ?? "";
}

/** Find the fixed version most relevant to a product in the mitigation text. */
function fixedVersionForProduct(
  mitigation: string,
  product: string,
): string | undefined {
  const normalizedProduct = product.toLowerCase();
  const sentences = mitigation.split(/(?<=\.)\s+/);
  const relevant =
    sentences.find((sentence) =>
      sentence.toLowerCase().includes(normalizedProduct)
    ) ?? sentences[0] ?? mitigation;
  return relevant.match(/Version\s+([0-9]+(?:\.[0-9]+){1,3})\s+or\s+later/i)
    ?.[1];
}

/** Determine whether the provided current product/version is affected. */
function currentStatus(
  affectedProducts: string,
  mitigation: string,
  currentProduct?: string,
  currentVersion?: string,
): { status?: Finding["currentStatus"]; fixedVersion?: string } {
  if (!currentProduct) return {};
  const product = currentProduct.toLowerCase();
  if (!affectedProducts.toLowerCase().includes(product)) {
    return { status: "not_applicable" };
  }
  if (!currentVersion) return { status: "unknown" };
  const fixedVersion = fixedVersionForProduct(mitigation, currentProduct);
  if (!fixedVersion) return { status: "unknown" };
  return {
    fixedVersion,
    status: compareVersions(currentVersion, fixedVersion) >= 0
      ? "patched"
      : "affected",
  };
}

/** Parse one official Ubiquiti release/bulletin into CVE findings. */
function parseUbiquitiBulletin(
  item: Record<string, unknown>,
  currentProduct?: string,
  currentVersion?: string,
): Finding[] {
  const notes =
    (item.importantNotes as Array<Record<string, string>> | undefined) ?? [];
  const html = notes.map((note) => note.content ?? "").join("\n");
  const text = htmlToText(html);
  const published = text.match(/Published:\s*([^\n]+)/i)?.[1]?.trim() ??
    (item.createdAt as string | undefined) ?? "";
  const bulletin = `${item.title as string} (${item.version as string})`;
  const url = `https://community.ui.com/releases/${item.slug as string}/${item
    .id as string}`;

  const sections = text.split(/Summary\s+\d+\s+of\s+\d+/i).slice(1);
  const findings: Finding[] = [];
  for (const section of sections) {
    const cves = [...section.matchAll(/CVE-\d{4}-\d{4,}/g)].map((m) => m[0]);
    if (cves.length === 0) continue;

    const affectedProducts = extractLabeled(section, "Affected Products");
    const mitigation = extractLabeled(section, "Mitigation");
    const base = section.match(/Base Score:\s*([0-9.]+)\s*(Critical|High)/i);
    const score = Number.parseFloat(base?.[1] ?? "0");
    const severity =
      (base?.[2]?.toUpperCase() === "CRITICAL" ? "CRITICAL" : "HIGH") as
        | "HIGH"
        | "CRITICAL";
    const description = section
      .split(/Affected Products:?/i)[0]
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 500);
    const status = currentStatus(
      affectedProducts,
      mitigation,
      currentProduct,
      currentVersion,
    );

    for (const cveId of new Set(cves)) {
      findings.push({
        cve_id: cveId,
        description,
        severity_score: score,
        severity,
        source: "UBIQUITI",
        published,
        bulletin,
        affectedProducts,
        mitigation,
        fixedVersion: status.fixedVersion,
        currentProduct,
        currentVersion,
        currentStatus: status.status,
        references: [url, `https://www.cve.org/CVERecord?id=${cveId}`],
      });
    }
  }
  return findings;
}

/** Query official Ubiquiti Community Security Advisory Bulletins. */
async function queryUbiquitiBulletins(
  maxResults: number,
  currentProduct?: string,
  currentVersion?: string,
): Promise<Finding[]> {
  const query = `
    query GetReleases($limit: Int, $searchTerm: String, $sortBy: ReleasesSortBy) {
      releases(limit: $limit, searchTerm: $searchTerm, sortBy: $sortBy) {
        items {
          id
          title
          slug
          version
          createdAt
          updatedAt
          tags
          importantNotes { type ... on TextContent { content } }
        }
      }
    }
  `;
  const data = await fetchJson("https://community.svc.ui.com/", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "origin": "https://community.ui.com",
      "referer": "https://community.ui.com/",
    },
    body: JSON.stringify({
      query,
      variables: {
        limit: Math.min(maxResults, 50),
        searchTerm: "Security Advisory Bulletin",
        sortBy: "LATEST",
      },
    }),
  }) as Record<string, unknown> | null;

  const releases =
    ((data?.data as Record<string, unknown> | undefined)?.releases as
      | Record<string, unknown>
      | undefined)?.items as Record<string, unknown>[] | undefined;
  if (!releases) return [];
  return releases.flatMap((item) =>
    parseUbiquitiBulletin(item, currentProduct, currentVersion)
  );
}

/** Query NVD REST API for CVEs matching keywords. */
async function queryNvd(
  keywords: string[],
  maxResults: number,
): Promise<Finding[]> {
  const queries = [
    "ubiquiti unifi",
    "unifi os",
    "dream machine",
    "unifi network",
  ];
  const keywordSet = new Set(keywords.map((k) => k.toLowerCase()));
  const findings: Finding[] = [];

  for (const q of queries) {
    const encoded = encodeURIComponent(q);
    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encoded}&resultsPerPage=${maxResults}`;
    const data = await fetchJson(url) as Record<string, unknown> | null;
    const vulns = data?.vulnerabilities as unknown[] | undefined;
    if (!vulns) continue;

    for (const vuln of vulns) {
      const cve = (vuln as Record<string, unknown>).cve as
        | Record<string, unknown>
        | undefined;
      if (!cve) continue;
      const descriptions = (cve.descriptions as unknown[] ?? []) as Record<
        string,
        string
      >[];
      const desc = descriptions.at(0)?.value ?? "";
      if (!Array.from(keywordSet).some((k) => desc.toLowerCase().includes(k))) {
        continue;
      }
      const cveYear = Number.parseInt(
        String(cve.id ?? "").match(/^CVE-(\d{4})-/)?.[1] ?? "0",
        10,
      );
      if (!cveYear || cveYear < new Date().getFullYear() - 1) continue;
      const published = (cve.published as string | undefined) ??
        (cve.publishedDate as string | undefined) ?? "";
      if (!isRecentIso(published)) continue;

      const metrics = (cve.metrics as Record<string, unknown>) ?? {};
      const allMetrics = [
        ...((metrics.cvssMetricV31 as unknown[]) ?? []),
        ...((metrics.cvssMetricV30 as unknown[]) ?? []),
      ];
      const firstMetric = allMetrics[0] as Record<string, unknown> | undefined;
      const cvss = firstMetric?.cvssData as Record<string, string> | undefined;
      const severity = cvss?.baseSeverity ?? "";
      if (severity !== "HIGH" && severity !== "CRITICAL") continue;

      findings.push({
        cve_id: cve.id as string,
        description: desc.slice(0, 500),
        severity_score: Number.parseFloat(cvss?.baseScore ?? "0"),
        severity: severity as "HIGH" | "CRITICAL",
        source: "NVD",
        published,
        references: (cve.references as unknown[] ?? [])
          .map((r) => (r as Record<string, string>)?.url ?? "")
          .filter((r) => r),
      });
    }
  }
  return findings;
}

/** Query GitHub Advisory DB for advisories matching keywords. */
async function queryGithubAdvisories(keywords: string[]): Promise<Finding[]> {
  const data = await fetchJson(
    "https://api.github.com/advisories?per_page=100",
    {
      headers: { Accept: "application/vnd.github+json" },
    },
  ) as unknown;
  if (!Array.isArray(data)) return [];

  const keywordSet = new Set(keywords.map((k) => k.toLowerCase()));
  const findings: Finding[] = [];
  for (const adv of data.slice(0, 100)) {
    const advObj = adv as Record<string, unknown>;
    const comb = `${advObj.title ?? ""} ${advObj.summary ?? ""}`.toLowerCase();
    if (!Array.from(keywordSet).some((k) => comb.includes(k))) continue;
    const severity = String(advObj.severity ?? "");
    if (severity !== "critical" && severity !== "high") continue;
    findings.push({
      cve_id: String(advObj.cve_id ?? `GHSA-${advObj.id}`),
      description: String(advObj.summary ?? "").slice(0, 500),
      severity_score: severity === "critical" ? 9.0 : 7.5,
      severity: severity.toUpperCase() as "HIGH" | "CRITICAL",
      source: "GITHUB",
      published: String(advObj.published_at ?? ""),
      references: ((advObj.references as unknown[] | undefined) ?? [])
        .map((r) => (r as Record<string, string>)?.url ?? "")
        .filter((r) => r),
    });
  }
  return findings;
}

/** Format alert text for new CVEs. */
function formatAlert(newCves: Finding[], timestamp: string): string {
  if (newCves.length === 0) return "";

  let text = "# UNIFI/UBIQUITI CVE WATCH ALERT\n\n";
  text += `Checked: ${timestamp}\n`;
  text += `New HIGH/CRITICAL CVEs/advisories: ${newCves.length}\n\n`;

  const sorted = [...newCves].sort((a, b) =>
    b.severity_score - a.severity_score
  );
  for (const cve of sorted) {
    const emoji = cve.severity === "CRITICAL" ? "RED" : "ORANGE";
    text +=
      `${emoji} **${cve.cve_id}** (${cve.severity}, score ${cve.severity_score})`;
    if (cve.source === "UBIQUITI" && cve.bulletin) text += ` — ${cve.bulletin}`;
    text += "\n";
    text += `   ${cve.description}\n`;
    if (cve.currentStatus) {
      text += `   Current ${cve.currentProduct ?? "product"} ${
        cve.currentVersion ?? "version unknown"
      }: ${cve.currentStatus}`;
      if (cve.fixedVersion) text += ` (fixed in ${cve.fixedVersion}+)`;
      text += "\n";
    }
    if (cve.references.length > 0) text += `   _${cve.references[0]}_\n`;
    text += "\n";
  }

  text += "---\n";
  text +=
    "Official Ubiquiti Security Advisory Bulletins are checked before NVD/GitHub.\n";
  text += "Next check will only alert on newly seen CVE IDs.\n";
  return text;
}

/**
 * Model definition for checking UniFi/Ubiquiti CVE sources.
 */
export const model = {
  type: "@mgreten/unifi-cve-watcher",
  version: "2026.06.13.1",

  methods: {
    run: {
      description:
        "Query official Ubiquiti Security Advisory Bulletins, NVD, and GitHub Advisory DB for new UniFi/Ubiquiti HIGH/CRITICAL CVEs.",
      arguments: CHECK_ARGS,
      resources: {
        results: {
          description: "Scan results and discovered CVEs",
          schema: CHECK_OUTPUT,
          lifetime: "infinite",
          garbageCollection: 0,
        },
      },
      execute: async (args: z.infer<typeof CHECK_ARGS>, ctx) => {
        const keywords = args.keywords || DEFAULT_KEYWORDS;
        const maxResults = args.maxResults ?? 20;
        const startTime = new Date().toISOString();

        const state = await loadState(ctx.repoDir);
        const checkedIds = new Set(state.checkedCves);

        const [ubiquitiData, nvdData, ghData] = await Promise.all([
          queryUbiquitiBulletins(
            maxResults,
            args.currentProduct,
            args.currentVersion,
          ),
          queryNvd(keywords, maxResults),
          queryGithubAdvisories(keywords),
        ]);

        const byId = new Map<string, Finding>();
        for (const cve of [...ubiquitiData, ...nvdData, ...ghData]) {
          if (
            !byId.has(cve.cve_id) || byId.get(cve.cve_id)?.source !== "UBIQUITI"
          ) {
            byId.set(cve.cve_id, cve);
          }
        }

        const allInScope = [...byId.values()].filter((cve) =>
          cve.severity === "HIGH" || cve.severity === "CRITICAL"
        );
        const newUncheckedCves = allInScope.filter((cve) =>
          !checkedIds.has(cve.cve_id)
        );
        const alertText = formatAlert(newUncheckedCves, startTime);

        const allIds = [
          ...new Set([
            ...state.checkedCves,
            ...allInScope.map((c) => c.cve_id),
          ]),
        ]
          .sort();
        await saveState(ctx.repoDir, {
          lastCheck: startTime,
          checkedCves: allIds,
        });

        return {
          dataHandles: [
            await ctx.writeResource("results", "scan", {
              alertText,
              newCVEs: newUncheckedCves,
              totalScanned: allInScope.length,
              timestamp: startTime,
            }),
          ],
        };
      },
    },
  },
};
