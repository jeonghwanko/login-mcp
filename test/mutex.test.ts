import assert from "node:assert/strict";
import test from "node:test";
import { createMutex } from "../src/mutex.ts";

test("mutex runs queued work one at a time", async () => {
  const lock = createMutex();
  const order: string[] = [];
  let release: (() => void) | undefined;
  const hold = new Promise<void>((resolve) => {
    release = resolve;
  });
  const first = lock(async () => {
    order.push("a-start");
    await hold;
    order.push("a-end");
  });
  await Promise.resolve();
  const second = lock(async () => {
    order.push("b");
  });
  await Promise.resolve();
  assert.deepEqual(order, ["a-start"]);
  release!();
  await first;
  await second;
  assert.deepEqual(order, ["a-start", "a-end", "b"]);
});
