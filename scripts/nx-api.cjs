#!/usr/bin/env node
/**
 * nx-api.js — клиент WS-JSON-RPC API Rust-ноды NeXXuS (nexxusd 0.228.x).
 *
 * Rust-нода говорит не по HTTP, а по WebSocket с JSON-RPC 2.0 и обязательной
 * авторизацией токеном из `~/.nexxus/api.token` (или NEXXUS_API_TOKEN_FILE).
 * Этот модуль — единственное место, где живёт протокол: control-plane,
 * хранитель и трей ходят в ноду только через него.
 *
 * Использование как библиотека:
 *   const nx = require('./nx-api.js');
 *   const status = await nx.call('node_status');
 *
 * Использование из командной строки:
 *   node nx-api.js node_status
 *   node nx-api.js node_connect '{"addr":"..."}'
 */

'use strict';

const fs = require('fs');

const API_ADDR = process.env.NEXXUS_API_ADDR || '127.0.0.1:4010';
const TOKEN_FILE = process.env.NEXXUS_API_TOKEN_FILE || '/etc/nexxus-rust/api.token';

/** Токен доступа к API ноды. */
function readToken() {
  try {
    return fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  } catch {
    return '';
  }
}

/**
 * WebSocket-реализация: сначала встроенная в Node (>= 22), затем пакет `ws`.
 * Встроенная предпочтительна — не зависит от node_modules на хосте.
 */
function getWebSocketImpl() {
  if (typeof globalThis.WebSocket === 'function') return globalThis.WebSocket;
  try {
    const mod = require('ws');
    return mod.WebSocket || mod;
  } catch {
    return null;
  }
}

/**
 * Вызов метода API ноды.
 * @param {string} method  имя метода (node_status, node_tor, …)
 * @param {object} params  параметры
 * @param {object} opts    { timeoutMs }
 * @returns {Promise<any>} результат метода
 */
function call(method, params = {}, opts = {}) {
  const WS = getWebSocketImpl();
  if (!WS) {
    return Promise.reject(new Error('нет WebSocket-реализации (нужен Node >= 22 или пакет ws)'));
  }
  const token = readToken();
  const timeoutMs = opts.timeoutMs || 20000;
  const url = `ws://${API_ADDR}/`;

  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new WS(url);
    } catch (e) {
      reject(new Error(`не удалось открыть ${url}: ${e.message}`));
      return;
    }
    let settled = false;
    const timer = setTimeout(() => {
      finish(new Error(`таймаут ${timeoutMs} мс: нода не ответила на «${method}»`));
    }, timeoutMs);

    function finish(err, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws.close(); } catch { /* уже закрыт */ }
      if (err) reject(err);
      else resolve(value);
    }

    ws.onopen = () => {
      try {
        ws.send(JSON.stringify({ method: 'auth', params: { token } }));
      } catch (e) {
        finish(new Error(`не удалось отправить auth: ${e.message}`));
      }
    };
    ws.onerror = (ev) => {
      const msg = (ev && (ev.message || ev.error && ev.error.message)) || 'соединение не установлено';
      finish(new Error(`WS: ${msg}`));
    };
    ws.onclose = () => finish(new Error('нода закрыла соединение'));
    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data));
      } catch {
        return; // мусор в кадре — игнорируем
      }
      if (msg.error) {
        const e = msg.error;
        finish(new Error((e && e.message) || JSON.stringify(e)));
        return;
      }
      const result = msg.result;
      // Первый ответ — результат auth; после него шлём сам метод.
      if (result && result.authenticated === true) {
        if (result.authenticated !== true) {
          finish(new Error('авторизация отклонена'));
          return;
        }
        try {
          ws.send(JSON.stringify({ method, params }));
        } catch (e) {
          finish(new Error(`не удалось отправить ${method}: ${e.message}`));
        }
        return;
      }
      finish(null, result);
    };
  });
}

/** Проверка живости ноды: node_status отвечает и авторизация прошла. */
async function isAlive(timeoutMs = 8000) {
  try {
    const st = await call('node_status', {}, { timeoutMs });
    return !!(st && st.node_id);
  } catch {
    return false;
  }
}

module.exports = { call, isAlive, readToken, API_ADDR, TOKEN_FILE };

// ── Режим командной строки ────────────────────────────────────────────────
if (require.main === module) {
  const method = process.argv[2];
  if (!method) {
    console.error('использование: node nx-api.js <method> [params-json]');
    process.exit(64);
  }
  let params = {};
  if (process.argv[3]) {
    try {
      params = JSON.parse(process.argv[3]);
    } catch (e) {
      console.error('невалидный JSON параметров: ' + e.message);
      process.exit(65);
    }
  }
  call(method, params)
    .then((r) => {
      process.stdout.write(JSON.stringify(r, null, 2) + '\n');
      process.exit(0);
    })
    .catch((e) => {
      console.error('ошибка: ' + e.message);
      process.exit(1);
    });
}
