#!/usr/bin/env node
/**
 * nexxus-control-server.cjs — всегда доступная панель управления Rust-нодой.
 *
 * Зачем он нужен, если у ноды есть свой API:
 *   Когда нода ОСТАНОВЛЕНА, её API не отвечает. Значит из дашборда,
 *   который отдаёт сама нода, нельзя нажать «Запустить» — страница уже
 *   недоступна. Это замкнутый круг: чтобы поднять ноду, нужна нода.
 *
 *   Этот сервер — control-plane: он живёт независимо от ноды (отдельный
 *   systemd-юнит), слушает ТОЛЬКО loopback и:
 *     - отдаёт дашборд (/opt/nexxus/dashboard);
 *     - переводит REST-эндпоинты дашборда в WS-JSON-RPC вызовы Rust-ноды
 *       (127.0.0.1:4010) и нормализует поля под интерфейс дашборда;
 *     - выполняет операции управления нодой даже когда она выключена;
 *     - читает и пишет конфигурацию (/etc/nexxus-rust/node.conf).
 *
 *   Через него дашборд работает всегда: http://127.0.0.1:3998/
 *
 * Безопасность:
 *   - слушает только 127.0.0.1, поэтому из сети недоступен;
 *   - токен ноды читается из файла 0640 root:nexxus и не попадает в ответы.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawnSync } = require('child_process');

const nx = require('./nx-api.cjs');

const CONTROL_PORT = parseInt(process.env.NEXXUS_CONTROL_PORT || '3998', 10);
const CONTROL_HOST = process.env.NEXXUS_CONTROL_HOST || '127.0.0.1';
const DASHBOARD_DIR = process.env.NEXXUS_DASHBOARD_DIR || '/opt/nexxus/dashboard';
const CONFIG_FILE = process.env.NEXXUS_CONFIG_FILE || '/etc/nexxus-rust/node.conf';
const NODE_UNIT = process.env.NEXXUS_UNIT || 'nexxus-rust-node.service';
const DATA_DIR = process.env.NEXXUS_DATA_DIR || '/var/lib/nexxus-rust';
const PAUSE_FILE = path.join(DATA_DIR, '.guardian-pause');
const GUARDIAN_LOG = path.join(DATA_DIR, 'logs', 'guardian.log');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

// ── Конфигурация Rust-ноды (node.conf) ────────────────────────────────────
// Ключи те же, что читает crates/nexxus-node/src/node_config.rs:
// env-переменная > node.conf > дефолт.
const CONFIG_SCHEMA = {
  api: { type: 'str', description: 'Адрес WS-API ноды (host:port)' },
  listen: { type: 'str', description: 'Адрес P2P-слушания (host:port)' },
  tor: { type: 'int', min: 0, max: 1, description: 'Tor через Arti: 1 = публиковать onion v3' },
  max_store_bytes: { type: 'int', min: 17179869184, max: 4398046511104, description: 'Пул хранилища, байт (кратно 16 ГБ)' },
  max_up_kbps: { type: 'int', min: 0, max: 10000000, description: 'Лимит исходящей полосы, кбит/с' },
  max_down_kbps: { type: 'int', min: 0, max: 10000000, description: 'Лимит входящей полосы, кбит/с' },
  threshold: { type: 'int', min: 0, max: 1000000000, description: 'Порог отсечения чанков, байт' },
  por_audit_secs: { type: 'int', min: 60, max: 604800, description: 'Интервал PoR-аудита, сек' },
  epoch_secs: { type: 'int', min: 30, max: 86400, description: 'Длительность эпохи, сек' },
};

function readConfig(file = CONFIG_FILE) {
  const out = {};
  if (!fs.existsSync(file)) return out;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq <= 0) continue;
    const key = t.slice(0, eq).trim();
    let value = t.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

function validatePatch(patch, current) {
  const values = {};
  const errors = [];
  for (const [key, raw] of Object.entries(patch || {})) {
    const spec = CONFIG_SCHEMA[key];
    if (!spec) {
      errors.push(`Неизвестный параметр: ${key}`);
      continue;
    }
    const rawValue = String(raw == null ? '' : raw).trim();
    if (spec.type === 'int') {
      const num = Number(rawValue);
      if (!Number.isFinite(num) || !Number.isInteger(num)) {
        errors.push(`${key}: ожидается целое число, получено «${rawValue}»`);
        continue;
      }
      if (spec.min !== undefined && num < spec.min) { errors.push(`${key}: минимум ${spec.min}`); continue; }
      if (spec.max !== undefined && num > spec.max) { errors.push(`${key}: максимум ${spec.max}`); continue; }
      if (key === 'max_store_bytes' && num % (16 * 1024 ** 3) !== 0) {
        errors.push(`${key}: значение должно быть кратно 16 ГБ (разделы по 16 ГБ)`);
        continue;
      }
      values[key] = String(num);
    } else {
      let value = rawValue;
      if (/[\n\r]/.test(value)) {
        errors.push(`${key}: значение не должно содержать перевод строки`);
        continue;
      }
      values[key] = value;
    }
  }
  return { values, errors };
}

function writeConfigPatch(values, file = CONFIG_FILE) {
  try {
    const raw = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const lines = raw ? raw.split('\n') : [];
    const seen = new Set();
    const out = [];
    for (const line of lines) {
      const t = line.trim();
      const eq = t.indexOf('=');
      const key = eq > 0 && !t.startsWith('#') ? t.slice(0, eq).trim() : null;
      if (key && Object.prototype.hasOwnProperty.call(values, key)) {
        out.push(`${key}=${values[key]}`);
        seen.add(key);
      } else {
        out.push(line);
      }
    }
    const missing = Object.entries(values).filter(([k]) => !seen.has(k));
    if (missing.length) {
      while (out.length && out[out.length - 1].trim() === '') out.pop();
      out.push('');
      out.push('# Добавлено через дашборд ноды');
      for (const [k, v] of missing) out.push(`${k}=${v}`);
    }
    // Пишем через временный файл и rename: systemd не должен увидеть
    // наполовину записанный конфиг.
    const tmp = `${file}.tmp.${process.pid}`;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(tmp, out.join('\n'), { mode: 0o644 });
    fs.renameSync(tmp, file);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ── Нормализация ответов Rust-ноды под интерфейс дашборда ────────────────
const GIB = 1024 ** 3;

function systemInfo() {
  return {
    hostname: os.hostname(),
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    cpus: os.cpus().length,
    loadAvg: os.loadavg(),
    totalMemMb: Math.round(os.totalmem() / 1024 / 1024),
    freeMemMb: Math.round(os.freemem() / 1024 / 1024),
  };
}

let lastPor = null;

/** Статус для дашборда: node_status + node_tor + метрики + хранилище. */
async function buildStatus() {
  const [st, tor, metrics, chunks] = await Promise.all([
    nx.call('node_status', {}, { timeoutMs: 8000 }).catch(() => null),
    nx.call('node_tor', {}, { timeoutMs: 8000 }).catch(() => null),
    nx.call('node_metrics', {}, { timeoutMs: 8000 }).catch(() => null),
    nx.call('node_chunks', {}, { timeoutMs: 8000 }).catch(() => null),
  ]);
  if (!st || !st.node_id) {
    throw new Error('нода не ответила');
  }
  const capBytes = (metrics && metrics.store_cap_bytes) || 0;
  const usedBytes = (metrics && metrics.store_used_bytes) || 0;
  const allocatedGb = capBytes ? Math.round((capBytes / GIB) * 100) / 100 : null;
  return {
    nodeId: st.node_id,
    onionAddress: (tor && tor.onion_address) || null,
    torEnabled: !!st.tor_enabled,
    torConnected: !!(tor && tor.connected),
    masterPublicKey: st.ed25519_pub,
    x25519PublicKey: st.x25519_pub,
    p2pEndpoint: st.listen_addr || st.bound_addr,
    uptimeSeconds: Math.round((st.uptime_ms || 0) / 1000),
    allocatedGb,
    reservedSections16Gb: capBytes ? Math.round(capBytes / GIB / 16) : null,
    usedBytes,
    freeBytes: (metrics && metrics.disk_free_bytes) || null,
    storedChunksCount: chunks ? chunks.total_chunks : null,
    chunkSizeBytes: chunks ? chunks.chunk_size_bytes : null,
    peersCount: st.peer_count != null ? st.peer_count : 0,
    lastPorLatencyMs: lastPor ? lastPor.elapsed_ms : null,
    paused: !!st.paused,
    version: st.version,
    storageDir: DATA_DIR,
    storeCapBytes: capBytes,
    rssKb: metrics ? metrics.rss_kb : null,
    system: systemInfo(),
    dynamicQuota: {
      personalVaultQuotaGb: allocatedGb,
      actualForeignChunksStoredGb: usedBytes ? Math.round((usedBytes / GIB) * 100) / 100 : 0,
    },
    antiLoop: {},
  };
}

/** Список пиров в формате дашборда. */
async function buildPeers() {
  const res = await nx.call('node_peers', {}, { timeoutMs: 8000 });
  const peers = (res && res.peers) || [];
  return peers.map((p) => ({
    nodeId: p.node_id || p.nodeId || '—',
    onionAddress: p.onion_address || p.onionAddress || '—',
    p2pEndpoint: p.addr || p.p2pEndpoint || '—',
    totalStorageAllocatedGb: p.storage_gb != null ? p.storage_gb : '—',
    uptimeSeconds: p.uptime_secs != null ? p.uptime_secs : 0,
    score: p.score != null ? p.score : null,
  }));
}

/** Хранилище в формате дашборда. */
async function buildChunks() {
  const res = await nx.call('node_chunks', {}, { timeoutMs: 8000 });
  const total = res && res.total_chunks ? res.total_chunks : 0;
  const used = res && res.used_bytes ? res.used_bytes : 0;
  const size = res && res.chunk_size_bytes ? res.chunk_size_bytes : 0;
  const chunks = [];
  for (let i = 0; i < Math.min(total, 40); i++) {
    chunks.push({ index: i, hash: '(чанк в redb, хэш вычисляется на месте)' });
  }
  return { count: total, totalBytes: used, chunkSizeBytes: size, chunks };
}

/** PoR-аудит в формате дашборда. */
async function buildPor() {
  const res = await nx.call('node_por', {}, { timeoutMs: 15000 });
  lastPor = res;
  return {
    verify: { verified: !!(res && res.ok) },
    challenge: {
      chunkIndex: 0,
      deadlineMs: 3000,
      chunkRoot: (res && res.chunk) || '—',
    },
    response: { respondedInMs: (res && res.elapsed_ms) || 0 },
    chunksTotal: (res && res.chunks_total) || 0,
  };
}

/** Метрики в формате «бенчмарка» для вкладки «Тесты». */
async function buildBenchmark() {
  const m = await nx.call('node_metrics', {}, { timeoutMs: 10000 });
  const metrics = (m && m.metrics) || {};
  const out = {};
  for (const [k, v] of Object.entries(metrics)) out[k] = v;
  out.rss_kb = m ? m.rss_kb : null;
  out.store_used_bytes = m ? m.store_used_bytes : null;
  out.store_cap_bytes = m ? m.store_cap_bytes : null;
  out.uptime_secs = m ? m.uptime_secs : null;
  out.disk_free_bytes = m ? m.disk_free_bytes : null;
  return out;
}

/** Логи ноды и хранителя. */
function buildLogs(lines) {
  const n = Math.max(1, Math.min(parseInt(lines || '120', 10) || 120, 2000));
  const out = [];
  const j = spawnSync('journalctl', ['-u', NODE_UNIT, '--no-pager', '-n', String(n)],
    { encoding: 'utf8', timeout: 15000 });
  if (j.stdout) out.push(...j.stdout.split('\n').filter(Boolean));
  if (fs.existsSync(GUARDIAN_LOG)) {
    try {
      const g = fs.readFileSync(GUARDIAN_LOG, 'utf8').split('\n').filter(Boolean);
      out.push('--- хранитель ---', ...g.slice(-Math.floor(n / 2)));
    } catch { /* лог недоступен */ }
  }
  return { logs: out };
}

// ── Управление нодой ──────────────────────────────────────────────────────
function systemctl(action) {
  const r = spawnSync('systemctl', [action, NODE_UNIT], { encoding: 'utf8', timeout: 30000 });
  return { ok: r.status === 0, output: ((r.stdout || '') + (r.stderr || '')).trim() };
}

function nodeAction(action) {
  if (!['start', 'stop', 'restart', 'status'].includes(action)) {
    return { ok: false, error: 'Действие: start|stop|restart|status' };
  }
  if (action === 'status') {
    const r = systemctl('is-active');
    return { ok: r.ok, action, output: r.output || 'unknown' };
  }
  try {
    if (action === 'stop') {
      fs.writeFileSync(PAUSE_FILE, `stopped via control panel at ${new Date().toISOString()}\n`);
    } else {
      fs.unlinkSync(PAUSE_FILE);
    }
  } catch { /* файл может отсутствовать */ }
  const r = systemctl(action);
  return { ok: r.ok, action, output: r.output || `команда «${action}» выполнена` };
}

// ── Статика дашборда ──────────────────────────────────────────────────────
function serveStatic(urlPath, res) {
  const rel = urlPath === '/' || urlPath === '' ? 'index.html' : decodeURIComponent(urlPath).replace(/^\/+/, '');
  const target = path.resolve(DASHBOARD_DIR, rel);
  const root = path.resolve(DASHBOARD_DIR);
  if (target !== root && !target.startsWith(root + path.sep)) return false;
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) return false;
  const ext = path.extname(target).toLowerCase();
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Cache-Control': 'no-cache',
  });
  res.end(fs.readFileSync(target));
  return true;
}

function json(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

/** Ошибка доступа к ноде — дашборд должен уметь показать «нода выключена». */
function offline(res, detail) {
  json(res, 503, {
    ok: false,
    offline: true,
    error: 'Нода не отвечает. Возможно, она остановлена.',
    detail: String(detail || ''),
  });
}

// ── HTTP-сервер ───────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = req.url || '/';
  const urlPath = url.split('?')[0];
  const query = new URLSearchParams(url.split('?')[1] || '');

  // Конфигурация — обрабатывается здесь, а не нодой: конфиг должен быть
  // доступен и при выключенной ноде.
  if (urlPath === '/api/config' && req.method === 'GET') {
    const current = readConfig();
    json(res, 200, {
      file: CONFIG_FILE,
      exists: fs.existsSync(CONFIG_FILE),
      values: current,
      effective: current,
      schema: CONFIG_SCHEMA,
      controlPanel: true,
      note: 'Параметры применяются после перезапуска ноды.',
    });
    return;
  }

  if (urlPath === '/api/config' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      try {
        const patch = JSON.parse(body || '{}');
        const { values, errors } = validatePatch(patch, readConfig());
        if (errors.length) { json(res, 400, { ok: false, errors }); return; }
        const written = writeConfigPatch(values);
        if (!written.ok) { json(res, 500, { ok: false, errors: [written.error] }); return; }
        const needsRestart = ['api', 'listen', 'tor', 'max_store_bytes'].some((k) => k in values);
        json(res, 200, {
          ok: true,
          applied: values,
          needsRestart,
          message: needsRestart
            ? 'Конфиг сохранён. Для применения нужно перезапустить ноду.'
            : 'Конфиг сохранён.',
        });
      } catch (e) {
        json(res, 400, { ok: false, errors: [e.message] });
      }
    });
    return;
  }

  if (urlPath === '/api/node/action' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      try {
        const { action } = JSON.parse(body || '{}');
        const result = nodeAction(action);
        json(res, result.error ? 400 : 200, result);
      } catch (e) {
        json(res, 400, { ok: false, error: e.message });
      }
    });
    return;
  }

  // ── Эндпоинты, которые отдаёт сама живая нода ──────────────────────────
  const nodeRoutes = {
    '/api/status': () => buildStatus(),
    '/api/peers': () => buildPeers(),
    '/api/chunks': () => buildChunks(),
    '/api/por/challenge': () => buildPor(),
    '/api/benchmark': () => buildBenchmark(),
    '/api/id': async () => {
      const [st, tor, doctor, metrics] = await Promise.all([
        nx.call('node_status', {}, { timeoutMs: 8000 }).catch(() => null),
        nx.call('node_tor', {}, { timeoutMs: 8000 }).catch(() => null),
        nx.call('node_doctor', {}, { timeoutMs: 8000 }).catch(() => null),
        nx.call('node_metrics', {}, { timeoutMs: 8000 }).catch(() => null),
      ]);
      if (!st) throw new Error('нода не ответила');
      const capBytes = (metrics && metrics.store_cap_bytes) || 0;
      const sys = systemInfo();
      return {
        nodeId: st.node_id,
        ed25519Pub: st.ed25519_pub,
        x25519Pub: st.x25519_pub,
        masterPublicKey: st.ed25519_pub,
        onionAddress: (tor && tor.onion_address) || null,
        version: st.version,
        port: (st.listen_addr || '').split(':').pop(),
        hostname: sys.hostname,
        os: sys.os,
        allocatedGb: capBytes ? Math.round((capBytes / GIB) * 100) / 100 : null,
        identityInitialized: doctor ? doctor.identity_initialized : null,
        seedVaultExists: doctor ? doctor.seed_vault_exists : null,
        encryptedAtRest: doctor ? doctor.encrypted_at_rest : null,
        storePath: doctor ? doctor.store_path : null,
        problems: doctor ? doctor.problems : [],
      };
    },
    '/api/logs': async () => buildLogs(query.get('lines')),
  };

  if (nodeRoutes[urlPath] && (req.method === 'GET' || req.method === 'POST')) {
    nodeRoutes[urlPath]()
      .then((data) => json(res, 200, data))
      .catch((e) => offline(res, e.message));
    return;
  }

  // Подключение к пиру.
  if (urlPath === '/api/peer/add' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      let peerUrl = '';
      try { peerUrl = String((JSON.parse(body || '{}').peerUrl) || '').trim(); } catch { /* пусто */ }
      if (!peerUrl) { json(res, 400, { ok: false, error: 'Укажите адрес пира' }); return; }
      nx.call('node_connect', { addr: peerUrl }, { timeoutMs: 20000 })
        .then((r) => json(res, 200, { ok: true, message: `подключение к ${peerUrl}: ${JSON.stringify(r)}` }))
        .catch((e) => json(res, 200, { ok: false, error: e.message }));
    });
    return;
  }

  // Статика дашборда.
  if (serveStatic(urlPath, res)) return;
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Dashboard not found');
});

server.listen(CONTROL_PORT, CONTROL_HOST, () => {
  console.log(`NeXXuS control panel: http://${CONTROL_HOST}:${CONTROL_PORT}/`);
  console.log(`Rust-нода: ws://${nx.API_ADDR} · юнит: ${NODE_UNIT} · токен: ${nx.TOKEN_FILE}`);
});

// Периодически обновляем задержку PoR для карточки «PoR, мс».
setInterval(() => {
  nx.call('node_por', {}, { timeoutMs: 15000 })
    .then((r) => { lastPor = r; })
    .catch(() => { /* нода может быть выключена — не шумим */ });
}, 60000).unref();
