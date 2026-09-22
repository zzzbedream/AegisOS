import assert from "node:assert/strict";
import test from "node:test";
import { startDashboard } from "../src/server.js";

test("dashboard exposes an enforced, read-only health endpoint", async () => {
  const dashboard = await startDashboard();
  try {
    const response = await fetch(`${dashboard.url}/api/health`);
    assert.equal(response.status, 200);
    const payload = await response.json() as { mode: string; testnetOnly: boolean };
    assert.equal(payload.mode, "enforced");
    assert.equal(payload.testnetOnly, true);
  } finally {
    await dashboard.close();
  }
});

test("dashboard refuses a non-loopback bind", async () => {
  await assert.rejects(() => startDashboard({ host: "0.0.0.0" }));
});
