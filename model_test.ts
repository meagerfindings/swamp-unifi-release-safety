import { model } from "./model.ts";

type Write = { spec: string; name: string; value: unknown };

function context(
  prior: unknown = null,
  writes: Write[] = [],
) {
  return {
    globalArgs: {},
    logger: {
      info: (_message: string, _properties?: Record<string, unknown>) => {},
    },
    readResource: async (_name: string) => prior,
    writeResource: async (spec: string, name: string, value: unknown) => {
      writes.push({ spec, name, value });
      return { name };
    },
  };
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function rejects(operation: () => Promise<unknown>, message: string) {
  try {
    await operation();
  } catch {
    return;
  }
  throw new Error(message);
}

Deno.test("scan fails before making a request when Home Assistant config is absent", async () => {
  const writes: Write[] = [];
  await rejects(
    () => model.methods.scan.execute({}, context(null, writes)),
    "scan should require Home Assistant configuration",
  );
  assert(writes.length === 0, "scan must not write when preflight fails");
});

Deno.test("observe records only changed direct observations as an initial review", async () => {
  const writes: Write[] = [];
  const result = await model.methods.observe.execute({
    observations: [
      {
        model: "U6-Pro",
        installedVersion: "6.6.65",
        targetVersion: "6.7.1",
        deviceId: "ap-living-room",
      },
      {
        model: "U6-Lite",
        installedVersion: "6.6.65",
        targetVersion: "6.6.65",
      },
    ],
  }, context(null, writes));

  assert(writes.length === 1, "observe should persist one report");
  assert(writes[0].spec === "releaseSafetyReport", "wrong resource type");
  const report = writes[0].value as {
    availableUpdates: Array<{ key: string; source: string }>;
    reviewCandidates: Array<{ key: string; stage: string }>;
  };
  assert(
    report.availableUpdates.length === 1,
    "unchanged firmware was retained",
  );
  assert(
    report.availableUpdates[0].key === "direct:ap-living-room:6.6.65->6.7.1" &&
      report.availableUpdates[0].source === "direct",
    "direct observation identity/source was not preserved",
  );
  assert(
    report.reviewCandidates[0]?.stage === "initial",
    "new firmware target should require an initial review",
  );
  assert(result.dataHandles.length === 1, "expected one output handle");
});

Deno.test("acknowledge advances only a currently due review stage", async () => {
  const key = "direct:ap-office:6.6.65->6.7.1";
  const prior = {
    scannedAt: "2026-10-14T00:00:00.000Z",
    availableUpdates: [{
      key,
      source: "direct",
      model: "U6-Pro",
      deviceId: "ap-office",
      deviceName: "ap-office",
      installedVersion: "6.6.65",
      targetVersion: "6.7.1",
      firstSeenAt: "2020-01-01T00:00:00.000Z",
      lastSeenAt: "2026-10-14T00:00:00.000Z",
    }],
    reviewCandidates: [],
    staleReleaseKeys: [],
    summary: "one review due",
  };
  const writes: Write[] = [];
  await rejects(
    () =>
      model.methods.acknowledge.execute({
        acknowledgements: [{ key, stage: "day7" }],
      }, context(prior, writes)),
    "a future review stage must not be acknowledged early",
  );
  assert(writes.length === 0, "rejected acknowledgement must not write");

  const acceptedWrites: Write[] = [];
  await model.methods.acknowledge.execute({
    acknowledgements: [{ key, stage: "initial" }],
  }, context(prior, acceptedWrites));
  assert(
    acceptedWrites.length === 1,
    "valid acknowledgement should persist one report",
  );
  const report = acceptedWrites[0].value as {
    availableUpdates: Array<
      { lastNotifiedStage?: string; nextReviewAt?: string }
    >;
    reviewCandidates: unknown[];
  };
  assert(
    report.availableUpdates[0]?.lastNotifiedStage === "initial" &&
      report.availableUpdates[0]?.nextReviewAt === "2020-01-08T00:00:00.000Z",
    "acknowledgement did not schedule the next review stage",
  );
  assert(
    report.reviewCandidates.length === 0,
    "acknowledged candidate stayed due",
  );
});
