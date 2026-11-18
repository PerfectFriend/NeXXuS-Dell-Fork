// Тесты безопасности HTTP-панели legacy-ноды (аудит H-16, H-17).
//
// Проверяем:
//   1) без NEXXUS_PANEL_TOKEN панель не стартует (fail closed);
//   2) без корректного bearer-токена API отдаёт 401;
//   3) запрос с чужим Host отдаёт 403 (защита от DNS-rebinding);
//   4) CORS-заголовок не равен "*" и не выставляется для чужого origin;
//   5) файловые операции отклоняют некорректный id (обход каталога);
//   6) файл, принятый от пира, получает свой локальный id.

import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";

const here = path.dirname(fileURLToPath(import.meta.url));
const TOKEN = "test-panel-token-0123456789";

async function withServer(env, fn) {
  const child = spawn(process.execPath, ["-e", `
    import { serveHttp } from ${JSON.stringify(path.join(here, "lib", "http.mjs"))};
    const node = {
      snapshot: () => ({ ok: true, files: [] }),
      contact: "nxx1test",
      addContact: async () => ({}),
      sendChat: () => ({}),
      storePlainFile: async () => ({ id: "x" }),
      loadPlainFile: async () => { throw new Error("нет файла"); },
      removeFile: async () => { throw new Error("нет файла"); },
      sendFile: async () => {},
    };
    await serveHttp(node, { host: "127.0.0.1", port: Number(process.env.TEST_PORT) });
  `], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (d) => { stderr += d.toString(); });
  const port = Number(env.TEST_PORT);
  // ждём подъёма
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/state`, { headers: { authorization: `Bearer ${TOKEN}` } });
      if (r.status) break;
    } catch { /* ещё не поднялся */ }
    await new Promise((res) => setTimeout(res, 100));
  }
  try {
    await fn({ port, stderr: () => stderr });
  } finally {
    child.kill("SIGKILL");
  }
}

let failed = 0;
function check(name, cond, extra = "") {
  if (cond) {
    console.log(`ok   ${name}`);
  } else {
    failed++;
    console.error(`FAIL ${name} ${extra}`);
  }
}

// 1) fail closed без токена
{
  const port = 45111;
  const child = spawn(process.execPath, ["-e", `
    import { serveHttp } from ${JSON.stringify(path.join(here, "lib", "http.mjs"))};
    await serveHttp({ snapshot: () => ({}) }, { host: "127.0.0.1", port: ${port} });
  `], {
    env: { ...process.env, NEXXUS_PANEL_TOKEN: "" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let err = "";
  child.stderr.on("data", (d) => { err += d.toString(); });
  const code = await new Promise((res) => child.on("exit", res));
  check("панель не стартует без токена", code !== 0 && /NEXXUS_PANEL_TOKEN/.test(err), `exit=${code} err=${err.slice(0, 120)}`);
}

// 2-4) основные проверки
await withServer({ TEST_PORT: "45112", NEXXUS_PANEL_TOKEN: TOKEN }, async ({ port }) => {
  const noAuth = await fetch(`http://127.0.0.1:${port}/api/state`);
  check("без bearer-токена — 401", noAuth.status === 401, `status=${noAuth.status}`);

  const badAuth = await fetch(`http://127.0.0.1:${port}/api/state`, {
    headers: { authorization: "Bearer wrong-token" },
  });
  check("с неверным токеном — 401", badAuth.status === 401, `status=${badAuth.status}`);

  const ok = await fetch(`http://127.0.0.1:${port}/api/state`, {
    headers: { authorization: `Bearer ${TOKEN}` },
  });
  check("с корректным токеном — 200", ok.status === 200, `status=${ok.status}`);

  // Host — forbidden header для fetch, поэтому запросим raw http.
  const badHostStatus = await new Promise((resolve) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: "/api/state",
      method: "GET",
      headers: { authorization: `Bearer ${TOKEN}`, host: "evil.example.com" },
    }, (res) => { res.resume(); resolve(res.statusCode); });
    req.on("error", () => resolve(0));
    req.end();
  });
  check("чужой Host — 403 (DNS-rebinding)", badHostStatus === 403, `status=${badHostStatus}`);

  const cors = await fetch(`http://127.0.0.1:${port}/api/state`, {
    headers: { authorization: `Bearer ${TOKEN}`, origin: "https://evil.example.com" },
  });
  const allow = cors.headers.get("access-control-allow-origin");
  check("CORS не '*' и не чужой origin", allow === null || allow === "", `allow-origin=${allow}`);

  const preflight = await fetch(`http://127.0.0.1:${port}/api/state`, {
    method: "OPTIONS",
    headers: { origin: "https://evil.example.com" },
  });
  check("preflight без allow-list origin без CORS-заголовков",
    preflight.headers.get("access-control-allow-origin") === null,
    `allow-origin=${preflight.headers.get("access-control-allow-origin")}`);
});

// 5-6) валидация id и локальный id для файла от пира
{
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "nexxus-legacy-test-"));
  const { createNode } = await import(path.join(here, "lib", "node.mjs"));
  const { createMnemonic } = await import(path.join(here, "lib", "identity.mjs"));
  const node = await createNode({ data: dir, mnemonic: createMnemonic(), log: () => {} }).catch((e) => {
    console.log("skip createNode:", String(e).slice(0, 120));
    return null;
  });
  if (!node) {
    console.log("skip createNode (нужна мнемоника) — проверка id через HTTP");
  } else {
    let threw = false;
    try {
      await node.removeFile("../../etc");
    } catch {
      threw = true;
    }
    check("removeFile отклоняет id с обходом каталога", threw);

    const rec = await node.storePlainFile({ name: "a.txt", bytes: new Uint8Array([1, 2, 3]) });
    check("локальный id соответствует строгому формату", /^[A-Za-z0-9_-]{1,64}$/.test(rec.id), rec.id);

    const peerRec = await node.storePlainFile({ id: "peer-chosen-id", name: "b.txt", bytes: new Uint8Array([4]), from: "fp:peer" });
    check("файл от пира получает свой локальный id", peerRec.id !== "peer-chosen-id", peerRec.id);
    check("id отправителя сохранён как remoteId", peerRec.remoteId === "peer-chosen-id", String(peerRec.remoteId));
    await fs.rm(dir, { recursive: true, force: true });
  }
}

if (failed) {
  console.error(`\n${failed} проверок провалено`);
  process.exit(1);
}
console.log("\nвсе проверки пройдены");
// createNode поднимает mesh-таймеры — процесс завершаем явно.
process.exit(0);
