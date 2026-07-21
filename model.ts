/**
 * UniFi firmware release-safety discovery model.
 *
 * Two independent, read-only collection modes feed the same deduplicated
 * review pipeline:
 *  - `scan`: reads Home Assistant's UniFi firmware update entities.
 *  - `observe`: records caller-supplied model/version observations for
 *    callers without Home Assistant (no network request, no credentials).
 *
 * Both modes share the same dedupe key strategy and the same initial plus
 * 7/14/21-day review-scheduling logic. It never installs updates or changes
 * Home Assistant/UniFi configuration.
 *
 * @module
 */
import { z } from "npm:zod@4";

const GlobalArgs = z.object({
  homeAssistantUrl: z.string().url().optional().describe(
    "Home Assistant base URL; only required to call scan",
  ),
  homeAssistantToken: z.string().meta({ sensitive: true }).optional().describe(
    "Read-only Home Assistant long-lived access token; only required to call scan",
  ),
  entityIds: z.array(z.string()).optional().describe(
    "Explicit Home Assistant firmware-update entity IDs to monitor; only required to call scan",
  ),
});

const ReleaseSchema = z.object({
  key: z.string(),
  source: z.enum(["homeAssistant", "direct"]).default("homeAssistant"),
  entityId: z.string().optional(),
  model: z.string().optional(),
  deviceId: z.string().optional(),
  deviceName: z.string(),
  installedVersion: z.string(),
  targetVersion: z.string(),
  releaseUrl: z.string().url().optional(),
  firstSeenAt: z.string(),
  lastSeenAt: z.string(),
  lastNotifiedStage: z.enum(["initial", "day7", "day14", "day21"]).optional(),
  nextReviewAt: z.string().optional(),
});

const ReviewCandidateSchema = ReleaseSchema.extend({
  stage: z.enum(["initial", "day7", "day14", "day21"]),
  researchRequired: z.boolean(),
  rationale: z.string(),
});

const ReportSchema = z.object({
  scannedAt: z.string(),
  firmwareEntitiesScanned: z.number().int().nonnegative().optional(),
  directObservationsRecorded: z.number().int().nonnegative().optional(),
  availableUpdates: z.array(ReleaseSchema),
  reviewCandidates: z.array(ReviewCandidateSchema),
  staleReleaseKeys: z.array(z.string()),
  summary: z.string(),
});

type Release = z.infer<typeof ReleaseSchema>;
type Report = z.infer<typeof ReportSchema>;
type Stage = z.infer<typeof ReviewCandidateSchema>["stage"];

type MethodContext = {
  globalArgs: z.infer<typeof GlobalArgs>;
  logger: {
    info: (message: string, properties?: Record<string, unknown>) => void;
  };
  readResource?: (name: string) => Promise<unknown>;
  writeResource: (
    resourceName: string,
    instanceName: string,
    value: Report,
  ) => Promise<unknown>;
};

type HaState = {
  entity_id?: unknown;
  state?: unknown;
  attributes?: Record<string, unknown>;
};

const REVIEW_DAYS: Record<Stage, number> = {
  initial: 0,
  day7: 7,
  day14: 14,
  day21: 21,
};

function isoAfter(start: string, days: number): string {
  return new Date(new Date(start).getTime() + days * 86_400_000).toISOString();
}

function nextStage(stage: Stage): Stage | undefined {
  return stage === "initial"
    ? "day7"
    : stage === "day7"
    ? "day14"
    : stage === "day14"
    ? "day21"
    : undefined;
}

function stageDue(release: Release, now: Date): Stage | undefined {
  const next: Stage | undefined = release.lastNotifiedStage === undefined
    ? "initial"
    : nextStage(release.lastNotifiedStage);
  if (!next) return undefined;
  return now >= new Date(isoAfter(release.firstSeenAt, REVIEW_DAYS[next]))
    ? next
    : undefined;
}

function reviewCandidatesFor(
  releases: Release[],
  now: Date,
): z.infer<typeof ReviewCandidateSchema>[] {
  const candidates: z.infer<typeof ReviewCandidateSchema>[] = [];
  for (const release of releases) {
    const stage = stageDue(release, now);
    if (!stage) continue;
    const upcoming = nextStage(stage);
    const nextReviewAt = upcoming
      ? isoAfter(release.firstSeenAt, REVIEW_DAYS[upcoming])
      : undefined;
    candidates.push({
      ...release,
      nextReviewAt,
      stage,
      researchRequired: true,
      rationale: stage === "initial"
        ? "New firmware target detected; verify official support and early reports."
        : `Scheduled ${stage} safety reassessment for the same firmware target.`,
    });
  }
  return candidates;
}

function firmwareUpdateFromState(
  item: HaState,
  now: string,
): Release | undefined {
  const entityId = typeof item.entity_id === "string" ? item.entity_id : "";
  const attributes = item.attributes ?? {};
  if (item.state !== "on" || attributes.device_class !== "firmware") {
    return undefined;
  }
  const installedVersion = typeof attributes.installed_version === "string"
    ? attributes.installed_version
    : "";
  const targetVersion = typeof attributes.latest_version === "string"
    ? attributes.latest_version
    : "";
  if (
    !entityId || !installedVersion || !targetVersion ||
    installedVersion === targetVersion
  ) {
    return undefined;
  }
  const deviceName = typeof attributes.friendly_name === "string"
    ? attributes.friendly_name
    : entityId;
  const releaseUrl = typeof attributes.release_url === "string" &&
      /^https?:\/\//.test(attributes.release_url)
    ? attributes.release_url
    : undefined;
  return {
    key: `${entityId}:${installedVersion}->${targetVersion}`,
    source: "homeAssistant",
    entityId,
    deviceName,
    installedVersion,
    targetVersion,
    releaseUrl,
    firstSeenAt: now,
    lastSeenAt: now,
  };
}

const ObservationSchema = z.object({
  model: z.string().min(1).describe(
    "Device hardware/software model identifier, e.g. a UniFi model name",
  ),
  installedVersion: z.string().min(1).describe(
    "Currently installed firmware version",
  ),
  targetVersion: z.string().min(1).describe(
    "Offered or available target firmware version",
  ),
  deviceId: z.string().min(1).optional().describe(
    "Optional caller-defined device identifier; used for deduplication instead of model when present",
  ),
  releaseUrl: z.string().url().optional().describe(
    "Optional URL to release notes or changelog for the target version",
  ),
});

function directObservationRelease(
  entry: z.infer<typeof ObservationSchema>,
  now: string,
): Release | undefined {
  const model = entry.model.trim();
  const installedVersion = entry.installedVersion.trim();
  const targetVersion = entry.targetVersion.trim();
  if (!model || !installedVersion || !targetVersion) return undefined;
  if (installedVersion === targetVersion) return undefined;
  const deviceId = entry.deviceId?.trim() || undefined;
  const identifier = deviceId ?? model;
  return {
    key: `direct:${identifier}:${installedVersion}->${targetVersion}`,
    source: "direct",
    model,
    deviceId,
    deviceName: deviceId ?? model,
    installedVersion,
    targetVersion,
    releaseUrl: entry.releaseUrl,
    firstSeenAt: now,
    lastSeenAt: now,
  };
}

const ObserveArgs = z.object({
  observations: z.array(ObservationSchema).min(1).describe(
    "Caller-supplied model/installed-version/target-version observations, gathered without Home Assistant",
  ),
});

const AcknowledgementArgs = z.object({
  acknowledgements: z.array(z.object({
    key: z.string(),
    stage: z.enum(["initial", "day7", "day14", "day21"]),
  })).min(1).describe(
    "Review candidates delivered to the user after research",
  ),
});

/** Model definition for read-only UniFi firmware release observation. */
export const model = {
  type: "@mgreten/unifi-release-safety",
  version: "2026.07.20.1",
  globalArguments: GlobalArgs,
  resources: {
    releaseSafetyReport: {
      description:
        "Current UniFi update inventory plus deduplicated review candidates, across Home Assistant and direct-observation sources",
      schema: ReportSchema,
      lifetime: "infinite",
      garbageCollection: 52,
    },
  },
  methods: {
    scan: {
      description:
        "Read Home Assistant firmware-update entities and emit only new or scheduled 7/14/21-day review candidates for that source. Does not install updates. Leaves any direct-observation entries untouched.",
      arguments: z.object({}),
      execute: async (_args: Record<string, never>, ctx: MethodContext) => {
        const { homeAssistantUrl, homeAssistantToken, entityIds } =
          ctx.globalArgs;
        if (!homeAssistantUrl || !homeAssistantToken || !entityIds?.length) {
          throw new Error(
            "scan requires homeAssistantUrl, homeAssistantToken, and at least one entityId to be configured on this model instance",
          );
        }
        const now = new Date();
        const nowIso = now.toISOString();
        ctx.logger.info("Reading Home Assistant firmware update entities");
        const base = homeAssistantUrl.replace(/\/$/, "");
        const response = await fetch(`${base}/api/states`, {
          headers: {
            Authorization: `Bearer ${homeAssistantToken}`,
            Accept: "application/json",
          },
          signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) {
          throw new Error(
            `Home Assistant states request failed with HTTP ${response.status}`,
          );
        }
        const states: unknown = await response.json();
        if (!Array.isArray(states)) {
          throw new Error("Home Assistant states response was not an array");
        }

        const prior = ReportSchema.nullable().parse(
          await ctx.readResource!("release-safety-current"),
        );
        const priorByKey = new Map(
          (prior?.availableUpdates ?? []).map((
            release,
          ) => [release.key, release]),
        );
        const firmwareStates = states.filter((item): item is HaState =>
          typeof item === "object" && item !== null &&
          typeof (item as HaState).entity_id === "string" &&
          entityIds.includes((item as HaState).entity_id as string)
        );
        const current = firmwareStates
          .map((item) => firmwareUpdateFromState(item, nowIso))
          .filter((item): item is Release => item !== undefined)
          .map((release) => {
            const previous = priorByKey.get(release.key);
            return previous ? { ...previous, lastSeenAt: nowIso } : release;
          })
          .sort((a, b) => a.key.localeCompare(b.key));

        const reviewCandidates = reviewCandidatesFor(current, now);

        const priorDirectReleases = (prior?.availableUpdates ?? []).filter((
          release,
        ) => release.source === "direct");
        const availableUpdates = [...current, ...priorDirectReleases].sort((
          a,
          b,
        ) => a.key.localeCompare(b.key));

        const priorHaKeys = new Set(
          (prior?.availableUpdates ?? [])
            .filter((release) => release.source === "homeAssistant")
            .map((release) => release.key),
        );
        const currentKeys = new Set(current.map((release) => release.key));
        const staleReleaseKeys = [...priorHaKeys]
          .filter((key) => !currentKeys.has(key))
          .sort();

        const summary = reviewCandidates.length === 0
          ? "No new or scheduled UniFi firmware safety reviews are due."
          : `${reviewCandidates.length} UniFi firmware safety review(s) due.`;
        const report: Report = {
          scannedAt: nowIso,
          firmwareEntitiesScanned: firmwareStates.length,
          availableUpdates,
          reviewCandidates,
          staleReleaseKeys,
          summary,
        };
        const handle = await ctx.writeResource(
          "releaseSafetyReport",
          "release-safety-current",
          report,
        );
        ctx.logger.info("Completed firmware update scan: {*}", {
          firmwareEntitiesScanned: firmwareStates.length,
          availableUpdates: current.length,
          reviewCandidates: reviewCandidates.length,
        });
        return { dataHandles: [handle] };
      },
    },
    observe: {
      description:
        "Record caller-supplied model/installed-version/target-version observations (no Home Assistant required) and emit only new or scheduled 7/14/21-day review candidates for that source. Performs no network request and does not install updates. Leaves any Home Assistant-sourced entries untouched.",
      arguments: ObserveArgs,
      execute: async (
        args: z.infer<typeof ObserveArgs>,
        ctx: MethodContext,
      ) => {
        const now = new Date();
        const nowIso = now.toISOString();
        ctx.logger.info("Recording direct-observation firmware entries: {*}", {
          observations: args.observations.length,
        });

        const prior = ReportSchema.nullable().parse(
          await ctx.readResource!("release-safety-current"),
        );
        const priorByKey = new Map(
          (prior?.availableUpdates ?? []).map((
            release,
          ) => [release.key, release]),
        );
        const current = args.observations
          .map((entry) => directObservationRelease(entry, nowIso))
          .filter((item): item is Release => item !== undefined)
          .map((release) => {
            const previous = priorByKey.get(release.key);
            return previous ? { ...previous, lastSeenAt: nowIso } : release;
          })
          .sort((a, b) => a.key.localeCompare(b.key));

        const reviewCandidates = reviewCandidatesFor(current, now);

        const priorOtherReleases = (prior?.availableUpdates ?? []).filter((
          release,
        ) => release.source !== "direct");
        const availableUpdates = [...priorOtherReleases, ...current].sort((
          a,
          b,
        ) => a.key.localeCompare(b.key));

        const priorDirectKeys = new Set(
          (prior?.availableUpdates ?? [])
            .filter((release) => release.source === "direct")
            .map((release) => release.key),
        );
        const currentKeys = new Set(current.map((release) => release.key));
        const staleReleaseKeys = [...priorDirectKeys]
          .filter((key) => !currentKeys.has(key))
          .sort();

        const summary = reviewCandidates.length === 0
          ? "No new or scheduled UniFi firmware safety reviews are due."
          : `${reviewCandidates.length} UniFi firmware safety review(s) due.`;
        const report: Report = {
          scannedAt: nowIso,
          directObservationsRecorded: args.observations.length,
          availableUpdates,
          reviewCandidates,
          staleReleaseKeys,
          summary,
        };
        const handle = await ctx.writeResource(
          "releaseSafetyReport",
          "release-safety-current",
          report,
        );
        ctx.logger.info("Completed direct-observation recording: {*}", {
          observationsRecorded: args.observations.length,
          availableUpdates: current.length,
          reviewCandidates: reviewCandidates.length,
        });
        return { dataHandles: [handle] };
      },
    },
    acknowledge: {
      description:
        "Record completed delivery of one or more research reports so the same firmware stage is not re-notified. Works for both Home Assistant and direct-observation entries.",
      arguments: AcknowledgementArgs,
      execute: async (
        args: z.infer<typeof AcknowledgementArgs>,
        ctx: MethodContext,
      ) => {
        const prior = ReportSchema.nullable().parse(
          await ctx.readResource!("release-safety-current"),
        );
        if (!prior) {
          throw new Error("No release-safety report exists to acknowledge");
        }
        const acknowledgements = new Map(
          args.acknowledgements.map((item) => [item.key, item.stage]),
        );
        const now = new Date();
        for (const acknowledgement of args.acknowledgements) {
          const release = prior.availableUpdates.find(
            (candidate) => candidate.key === acknowledgement.key,
          );
          if (!release) {
            throw new Error(
              `Acknowledgement key is not in the current release report: ${acknowledgement.key}`,
            );
          }
          const dueStage = stageDue(release, now);
          if (dueStage !== acknowledgement.stage) {
            throw new Error(
              `Acknowledgement stage ${acknowledgement.stage} is not currently due for ${acknowledgement.key}`,
            );
          }
        }
        const availableUpdates = prior.availableUpdates.map((release) => {
          const stage = acknowledgements.get(release.key);
          if (!stage) return release;
          const upcoming = nextStage(stage);
          const nextReviewAt = upcoming
            ? isoAfter(release.firstSeenAt, REVIEW_DAYS[upcoming])
            : undefined;
          return { ...release, lastNotifiedStage: stage, nextReviewAt };
        });
        const acknowledgedKeys = new Set(
          availableUpdates
            .filter((release) => acknowledgements.has(release.key))
            .map((release) => release.key),
        );
        if (acknowledgedKeys.size !== acknowledgements.size) {
          throw new Error(
            "One or more acknowledgement keys were not in the current release report",
          );
        }
        const report: Report = {
          ...prior,
          scannedAt: new Date().toISOString(),
          availableUpdates,
          reviewCandidates: [],
          summary:
            `Recorded delivery for ${acknowledgedKeys.size} UniFi firmware safety review(s).`,
        };
        const handle = await ctx.writeResource(
          "releaseSafetyReport",
          "release-safety-current",
          report,
        );
        ctx.logger.info("Recorded delivered firmware safety reviews: {*}", {
          acknowledgements: acknowledgedKeys.size,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
