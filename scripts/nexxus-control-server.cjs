#!/usr/bin/env node
/**
 * nexxus-control-server.js — всегда доступная панель управления нодой.
 *
 * Зачем он нужен, если у самой ноды есть HTTP API:
 *   Когда нода ОСТАНОВЛЕНА, её API не отвечает. Значит из дашборда,
 *   который отдаёт сама нода, нельзя нажать «Запустить» — страница уже
 *   недоступна. Это замкнутый круг: чтобы поднять ноду, нужна нода.
 *
 *   Этот сервер — control-plane: он живёт независимо от ноды (запущен
 *   отдельным systemd-юнитом), слушает ТОЛЬКО loopback и:
 *     - отдаёт дашборд (/opt/nexxus/dashboard)
 *     - проксирует /api/* к живой ноде (127.0.0.1:3999)
 *     - выполняет операции управления нодой, даже когда она выключена
 *       (start/stop/restart/status)
 *     - читает и пишет конфигурацию (/etc/nexxus/nexxus.conf)
 *
 *   Через него дашборд работает всегда: http://127.0.0.1:3998/
 *
 * Безопасность:
 *   - слушает только 127.0.0.1 (не 0.0.0.0), поэтому из сети недоступен;
 *   - операции управления выполняются от root, но доступны лишь
 *     локальному пользователю — как и любой другой инструмент на хосте.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');

const NODE_PORT = parseInt(process.env.NEXXUS_NODE_PORT || '3999', 10);
const CONTROL_PORT = parseInt(process.env.NEXXUS_CONTROL_PORT || '3998', 10);
const CONTROL_HOST = process.env.NEXXUS_CONTROL_HOST || '127.0.0.1';
const NODE_HOST = '127.0.0.1';
const DASHBOARD_DIR = process.env.NEXXUS_DASHBOARD_DIR || '/opt/nexxus/dashboard';
const CONFIG_FILE = process.env.NEXXUS_CONFIG_FILE || '/etc/nexxus/nexxus.conf';
const NODE_UNIT = process.env.NEXXUS_UNIT || 'nexxus-node.service';
const DATA_DIR = process.env.NEXXUS_DATA_DIR || '/var/lib/nexxus';
const PAUSE_FILE = path.join(DATA_DIR, '.guardian-pause');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

// ── Конфигурация ──────────────────────────────────────────────────────────
const CONFIG_SCHEMA = {
  NEXXUS_PORT: { type: 'int', min: 1, max: 65535, description: 'TCP-порт API и P2P-протокола' },
  NEXXUS_HOST: { type: 'str', values: ['0.0.0.0', '127.0.0.1'], description: 'Адрес прослушивания' },
  NEXXUS_STORAGE_GB: { type: 'int', min: 16, max: 4096, description: 'Пул хранилища, ГБ (кратно 16)' },
  NEXXUS_LOG_LEVEL: { type: 'str', values: ['debug', 'info', 'warn', 'error'], description: 'Уровень логирования' },
  NEXXUS_BOOTSTRAP_PEERS: { type: 'str', description: 'Bootstrap-пиры через запятую' },
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
      if (key === 'NEXXUS_STORAGE_GB' && num % 16 !== 0) {
        errors.push(`${key}: значение должно быть кратно 16 ГБ (разделы по 16 ГБ)`);
        continue;
      }
      values[key] = String(num);
    } else {
      let value = rawValue;
      if (spec.values && !spec.values.includes(value.toLowerCase())) {
        errors.push(`${key}: допустимые значения: ${spec.values.join(', ')}`);
        continue;
      }
      if (spec.values) value = value.toLowerCase();
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
    // наполовину записанный EnvironmentFile.
    const tmp = `${file}.tmp.${process.pid}`;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(tmp, out.join('\n'), { mode: 0o644 });
    fs.renameSync(tmp, file);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ── Проксирование к живой ноде ────────────────────────────────────────────
function proxyToNode(req, res, urlPath, method, body) {
  const opts = {
    hostname: NODE_HOST,
    port: NODE_PORT,
    path: urlPath,
    method,
    headers: { 'Content-Type': 'application/json' },
    timeout: 15000,
  };
  const proxied = http.request(opts, (nodeRes) => {
    res.writeHead(nodeRes.statusCode || 502, {
      'Content-Type': nodeRes.headers['content-type'] || 'application/json',
    });
    nodeRes.pipe(res);
  });
  proxied.on('timeout', () => proxied.destroy(new Error('node timeout')));
  proxied.on('error', (err) => {
    // Нода недоступна — отвечаем понятным JSON, а не рвём соединение:
    // дашборд должен уметь показать «нода выключена» и предложить поднять.
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: false,
      offline: true,
      error: 'Нода не отвечает. Возможно, она остановлена.',
      detail: err.message,
    }));
  });
  if (body) proxied.write(body);
  proxied.end();
}

// ── Управление нодой ──────────────────────────────────────────────────────
function systemctl(action) {
  const r = spawnSync('systemctl', [action, NODE_UNIT], { encoding: 'utf8', timeout: 30000 });
  return {
    ok: r.status === 0,
    output: ((r.stdout || '') + (r.stderr || '')).trim(),
  };
}

function nodeAction(action) {
  if (!['start', 'stop', 'restart', 'status'].includes(action)) {
    return { ok: false, error: 'Действие: start|stop|restart|status' };
  }
  if (action === 'status') {
    const r = systemctl('is-active');
    return { ok: r.ok, action, output: r.output || 'unknown' };
  }
  // Пауза хранителя: при остановке он не должен вернуть ноду автоматически.
  try {
    if (action === 'stop') {
      fs.writeFileSync(PAUSE_FILE, `stopped via control panel at ${new Date().toISOString()}\n`);
    } else {
      fs.unlinkSync(PAUSE_FILE);
    }
  } catch { /* файл может отсутствовать — это не ошибка */ }

  const r = systemctl(action);
  return {
    ok: r.ok,
    action,
    output: r.output || `команда «${action}» выполнена`,
  };
}

// ── Статика дашборда ──────────────────────────────────────────────────────
function serveStatic(urlPath, res) {
  const rel = urlPath === '/' || urlPath === '' ? 'index.html' : decodeURIComponent(urlPath).replace(/^\/+/, '');
  const target = path.resolve(DASHBOARD_DIR, rel);
  const root = path.resolve(DASHBOARD_DIR);
  // Защита от выхода за пределы каталога дашборда.
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

// ── HTTP-сервер ───────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const urlPath = (req.url || '/').split('?')[0];

  // Конфигурация — обрабатывается здесь, а не нодой: конфиг должен быть
  // доступен и при выключенной ноде.
  if (urlPath === '/api/config' && req.method === 'GET') {
    const current = readConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      file: CONFIG_FILE,
      exists: fs.existsSync(CONFIG_FILE),
      values: current,
      effective: current,
      schema: CONFIG_SCHEMA,
      controlPanel: true,
    }, null, 2));
    return;
  }

  if (urlPath === '/api/config' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const patch = JSON.parse(body || '{}');
        const { values, errors } = validatePatch(patch, readConfig());
        if (errors.length) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, errors }));
          return;
        }
        const written = writeConfigPatch(values);
        if (!written.ok) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, errors: [written.error] }));
          return;
        }
        const needsRestart = ['NEXXUS_PORT', 'NEXXUS_HOST', 'NEXXUS_STORAGE_GB']
          .some(k => k in values);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ok: true,
          applied: values,
          needsRestart,
          message: needsRestart
            ? 'Конфиг сохранён. Для применения нужно перезапустить ноду.'
            : 'Конфиг сохранён.',
        }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, errors: [e.message] }));
      }
    });
    return;
  }

  if (urlPath === '/api/node/action' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      try {
        const { action } = JSON.parse(body || '{}');
        const result = nodeAction(action);
        res.writeHead(result.error ? 400 : 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // Список файлов в хранилище — из мета-каталога ноды.
  if (urlPath === '/api/files' && req.method === 'GET') {
    try {
      const metaDir = path.join(DATA_DIR, 'meta');
      const files = fs.existsSync(metaDir)
        ? fs.readdirSync(metaDir)
          .filter(f => f.endsWith('.manifest.json'))
          .map(f => {
            const hash = f.replace(/\.manifest\.json$/, '');
            let size = 0, name = hash, created = null;
            try {
              const m = JSON.parse(fs.readFileSync(path.join(metaDir, f), 'utf8'));
              size = m.totalSizeBytes || 0;
              name = m.originalName || hash;
              created = m.createdAt || null;
            } catch { /* повреждённый манифест — покажем как есть */ }
            return { hash, name, size, created };
          })
        : [];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ count: files.length, files }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return;
  }

  // Остальные /api/* — проксируем к живой ноде.
  if (urlPath.startsWith('/api/')) {
    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', () => {
      proxyToNode(req, res, urlPath, req.method, body || null);
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
  console.log(`Нода: ${NODE_HOST}:${NODE_PORT} · юнит: ${NODE_UNIT}`);
});
