/**
 * nexxus-control.ts — управление конфигурацией и жизненным циклом ноды.
 *
 * Вынесено из linux-daemon.ts, чтобы файл демона не рос: здесь вся работа
 * с конфиг-файлом ноды (/etc/nexxus/nexxus.conf), командами systemd и
 * раздачей статики дашборда.
 *
 * Ключевое разделение ответственности:
 *   - Демон работает от root и может менять конфиг и дергать systemd.
 *   - Но дашборд открыт по HTTP, поэтому любые мутирующие операции
 *     принимаются ТОЛЬКО с loopback. Иначе любой в локальной сети,
 *     кто дотянулся до :3999, смог бы перезапустить ноду или дописать
 *     в конфиг.
 */

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';

export interface NexxusConfig {
  [key: string]: string;
}

/** Путь к конфиг-файлу. Переопределяется через NEXXUS_CONFIG_FILE. */
export const CONFIG_FILE = process.env.NEXXUS_CONFIG_FILE || '/etc/nexxus/nexxus.conf';

/** Каталог с дашбордом. */
export const DASHBOARD_DIR = process.env.NEXXUS_DASHBOARD_DIR || '/opt/nexxus/dashboard';

/** Юнит ноды — для start/stop/restart. */
export const NODE_UNIT = process.env.NEXXUS_UNIT || 'nexxus-node.service';

/**
 * Ключи конфига, которые меняет дашборд, и их допустимые значения.
 * Валидация нужна, потому что конфиг уходит в systemd EnvironmentFile:
 * опечатка там ломает старт ноды целиком.
 */
export const CONFIG_SCHEMA: Record<string, { type: 'int' | 'str' | 'bool'; min?: number; max?: number; values?: string[]; description: string }> = {
  NEXXUS_PORT: { type: 'int', min: 1, max: 65535, description: 'TCP-порт API и P2P-протокола' },
  NEXXUS_HOST: { type: 'str', values: ['0.0.0.0', '127.0.0.1'], description: 'Адрес прослушивания' },
  NEXXUS_STORAGE_GB: { type: 'int', min: 16, max: 4096, description: 'Пул хранилища, ГБ (кратно 16)' },
  NEXXUS_LOG_LEVEL: { type: 'str', values: ['debug', 'info', 'warn', 'error'], description: 'Уровень логирования' },
  NEXXUS_BOOTSTRAP_PEERS: { type: 'str', description: 'Bootstrap-пиры через запятую' },
};

/** Читает конфиг-файл в виде плоского словаря. */
export function readConfigFile(file: string = CONFIG_FILE): NexxusConfig {
  const out: NexxusConfig = {};
  if (!fs.existsSync(file)) return out;
  const raw = fs.readFileSync(file, 'utf8');
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    // Снимаем окружающие кавычки, если есть.
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

/** Проверяет и нормализует набор изменений. Возвращает {values, errors}. */
export function validateConfigPatch(
  patch: Record<string, unknown>,
  current: NexxusConfig,
): { values: Record<string, string>; errors: string[] } {
  const values: Record<string, string> = {};
  const errors: string[] = [];

  for (const [key, raw] of Object.entries(patch)) {
    const spec = CONFIG_SCHEMA[key];
    if (!spec) {
      errors.push(`Неизвестный параметр: ${key}`);
      continue;
    }
    const rawValue = String(raw ?? '').trim();

    if (spec.type === 'int') {
      const num = Number(rawValue);
      if (!Number.isFinite(num) || !Number.isInteger(num)) {
        errors.push(`${key}: ожидается целое число, получено «${rawValue}»`);
        continue;
      }
      if (spec.min !== undefined && num < spec.min) {
        errors.push(`${key}: минимум ${spec.min}`);
        continue;
      }
      if (spec.max !== undefined && num > spec.max) {
        errors.push(`${key}: максимум ${spec.max}`);
        continue;
      }
      // Пул хранилища режется на секции по 16 ГБ — иначе нода сообщает
      // о дробной секции и расчёт квоты врёт.
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
      // Значение попадает в EnvironmentFile systemd — перевод строки
      // сломает файл, а кавычки экранируют пробелы.
      if (/[\n\r]/.test(value)) {
        errors.push(`${key}: значение не должно содержать перевод строки`);
        continue;
      }
      values[key] = value;
    }
  }
  return { values, errors };
}

/**
 * Записывает изменения в конфиг-файл, сохраняя комментарии и порядок.
 * Перезаписывает только заданные ключи; остальные строки остаются как есть.
 */
export function writeConfigPatch(
  values: Record<string, string>,
  file: string = CONFIG_FILE,
): { ok: boolean; error?: string } {
  try {
    const raw = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const lines = raw ? raw.split('\n') : [];
    const seen = new Set<string>();
    const outLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      const eq = trimmed.indexOf('=');
      const key = eq > 0 && !trimmed.startsWith('#') ? trimmed.slice(0, eq).trim() : null;
      if (key && Object.prototype.hasOwnProperty.call(values, key)) {
        outLines.push(`${key}=${values[key]}`);
        seen.add(key);
      } else {
        outLines.push(line);
      }
    }

    // Новые ключи дописываем в конец.
    const missing = Object.entries(values).filter(([k]) => !seen.has(k));
    if (missing.length) {
      while (outLines.length && outLines[outLines.length - 1].trim() === '') outLines.pop();
      outLines.push('');
      outLines.push('# Добавлено через дашборд ноды');
      for (const [k, v] of missing) outLines.push(`${k}=${v}`);
    }

    // Пишем через временный файл и rename — systemd не должен увидеть
    // наполовину записанный EnvironmentFile.
    const tmp = `${file}.tmp.${process.pid}`;
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(tmp, outLines.join('\n'), { mode: 0o644 });
    fs.renameSync(tmp, file);
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

/** Текущее состояние конфига + значения по умолчанию + схема. */
export function describeConfig(file: string = CONFIG_FILE) {
  const current = readConfigFile(file);
  const effective: NexxusConfig = {};
  for (const key of Object.keys(CONFIG_SCHEMA)) {
    const envValue = process.env[key];
    const fileValue = current[key];
    // Приоритет как в systemd: EnvironmentFile перекрывает Environment=,
    // а фактически применяется то, что в Environment= юнита... но здесь
    // мы показываем файл как источник правды — он и есть то, что
    // применяется при следующем старте.
    effective[key] = fileValue ?? envValue ?? '';
  }
  return {
    file,
    exists: fs.existsSync(file),
    values: current,
    effective,
    schema: CONFIG_SCHEMA,
  };
}

/**
 * Выполняет systemctl-команду от имени текущего процесса.
 * Демон работает от root, поэтому подъём/остановка ноды доступны.
 */
export function systemctlAction(action: 'start' | 'stop' | 'restart' | 'status'): Promise<{ ok: boolean; output: string }> {
  return new Promise((resolve) => {
    const args = action === 'status' ? ['is-active', NODE_UNIT] : [action, NODE_UNIT];
    const proc = spawn('systemctl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    proc.stdout.on('data', d => { output += d.toString(); });
    proc.stderr.on('data', d => { output += d.toString(); });
    const timer = setTimeout(() => {
      proc.kill('SIGKILL');
      resolve({ ok: false, output: 'systemctl не ответил вовремя' });
    }, 30000);
    proc.on('close', (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, output: output.trim() });
    });
    proc.on('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, output: err.message });
    });
  });
}

/**
 * Планирует systemctl-команду и СРАЗУ возвращает управление.
 *
 * Зачем: systemctl restart nexxus-node останавливает САМ демон, который
 * этот вызов инициировал. Если ждать завершения systemctl, демон будет
 * убит systemd раньше, чем успеет отдать HTTP-ответ, и клиент увидит
 * обрыв соединения вместо результата.
 *
 * Поэтому команда запускается отдельным процессом с задержкой: ответ
 * уходит клиенту первым, а перезапуск происходит через полсекунды.
 */
export function scheduleSystemctlAction(action: 'start' | 'stop' | 'restart'): { ok: boolean; output: string } {
  try {
    // Задержка нужна, чтобы HTTP-ответ демона ушёл клиенту ДО того,
    // как systemd убьёт процесс. Без неё клиент видит обрыв соединения.
    // Выполняем через shell: 'sleep 1 && systemctl ...' — процесс
    // отсоединённый, поэтому переживёт смерть родителя-демона.
    const child = spawn('/bin/sh', ['-c', `sleep 1 && systemctl ${action} ${NODE_UNIT}`], {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
    return { ok: true, output: `команда «${action}» запланирована` };
  } catch (e: any) {
    return { ok: false, output: e.message };
  }
}

/** Проверяет, что запрос пришёл с loopback — мутирующие операции только оттуда. */
export function isLoopback(remoteAddress: string | undefined): boolean {
  if (!remoteAddress) return false;
  const addr = remoteAddress.replace(/^::ffff:/, '');
  return addr === '127.0.0.1' || addr === '::1' || addr.startsWith('127.');
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

/**
 * Отдаёт файл из каталога дашборда.
 * Защита от выхода за пределы каталога: путь нормализуется, и итоговый
 * путь обязан остаться внутри DASHBOARD_DIR.
 */
export function serveDashboardFile(
  urlPath: string,
  res: http.ServerResponse,
): boolean {
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
