// ============================================================================
// Neuro Grafic — Cloudflare Worker
// Настоящая проверка Telegram Login Widget (HMAC-SHA256) + хранение проектов в D1.
//
// Требуемые привязки, которые нужно добавить в панели Cloudflare
// (Workers & Pages → ваш Worker → Settings):
//
//   Bindings → D1 database:
//     Variable name: DB   (важно: ровно "DB", это имя используется в коде)
//     Database: ваша созданная D1-база
//
//   Variables and Secrets (обязательно тип "Secret", не "Text"):
//     TELEGRAM_BOT_TOKEN  — токен бота из @BotFather → /mybots → API Token
//     SESSION_SECRET      — любая длинная случайная строка (придумайте сами,
//                           40+ символов, никому не показывайте)
//
// Домен фронтенда, которому разрешено обращаться к этому Worker'у.
// Если сайт когда-нибудь переедет на свой домен — поменяйте строку ниже.
// ============================================================================

const ALLOWED_ORIGIN = "https://wzcasper.github.io";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // сессия действует 30 дней
const AUTH_MAX_AGE_SECONDS = 60 * 60 * 24;     // данные от виджета Telegram не старше 24 часов

// ---------------------------------------------------------------------------
// Вспомогательные функции
// ---------------------------------------------------------------------------

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders() },
  });
}

function b64urlEncode(input) {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecodeToString(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function hmacSha256(keyBytes, message) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
}

function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Проверка подписи Telegram Login Widget
// https://core.telegram.org/widgets/login#checking-authorization
// ---------------------------------------------------------------------------

async function verifyTelegramAuth(data, botToken) {
  const { hash, ...fields } = data;
  if (!hash || !botToken) return false;

  const checkString = Object.keys(fields)
    .filter((k) => fields[k] !== undefined && fields[k] !== null)
    .sort()
    .map((k) => `${k}=${fields[k]}`)
    .join("\n");

  const secretKey = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(botToken));
  const signature = await hmacSha256(new Uint8Array(secretKey), checkString);
  const computedHash = bytesToHex(signature);

  return timingSafeEqual(computedHash, String(hash));
}

// ---------------------------------------------------------------------------
// Сессия: подписанный токен вида payload.signature (без отдельной таблицы сессий).
// Токен несёт telegram_id и "версию сессии" пользователя — при выходе версия
// увеличивается в базе, и все ранее выданные токены сразу становятся недействительны.
// ---------------------------------------------------------------------------

async function createSessionToken(telegramId, sessionVersion, secret) {
  const payload = {
    sub: telegramId,
    sv: sessionVersion,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const payloadB64 = b64urlEncode(JSON.stringify(payload));
  const sig = await hmacSha256(new TextEncoder().encode(secret), payloadB64);
  return `${payloadB64}.${b64urlEncode(sig)}`;
}

async function verifySessionToken(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [payloadB64, sigB64] = token.split(".");
  const expectedSig = await hmacSha256(new TextEncoder().encode(secret), payloadB64);
  if (!timingSafeEqual(b64urlEncode(expectedSig), sigB64)) return null;
  try {
    const payload = JSON.parse(b64urlDecodeToString(payloadB64));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// Возвращает telegram_id, только если подпись верна, токен не истёк
// И версия сессии совпадает с текущей версией в базе (т.е. не было выхода/отзыва).
async function getAuthedTelegramId(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return null;

  const payload = await verifySessionToken(token, env.SESSION_SECRET);
  if (!payload) return null;

  const row = await env.DB.prepare(`SELECT session_version FROM users WHERE telegram_id = ?`)
    .bind(payload.sub)
    .first();

  if (!row || row.session_version !== payload.sv) return null;
  return payload.sub;
}

// ---------------------------------------------------------------------------
// Обработчик запросов
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      // ---- Вход через Telegram ----
      if (pathname === "/api/auth/telegram" && request.method === "POST") {
        const data = await request.json();

        const now = Math.floor(Date.now() / 1000);
        if (!data.auth_date || now - Number(data.auth_date) > AUTH_MAX_AGE_SECONDS) {
          return json({ error: "Данные авторизации устарели, попробуйте войти ещё раз" }, 401);
        }

        const valid = await verifyTelegramAuth(data, env.TELEGRAM_BOT_TOKEN);
        if (!valid) {
          return json({ error: "Не удалось подтвердить подпись Telegram" }, 401);
        }

        const telegramId = String(data.id);

        await env.DB.prepare(
          `INSERT INTO users (telegram_id, username, first_name, photo_url, updated_at)
           VALUES (?, ?, ?, ?, datetime('now'))
           ON CONFLICT(telegram_id) DO UPDATE SET
             username = excluded.username,
             first_name = excluded.first_name,
             photo_url = excluded.photo_url,
             updated_at = datetime('now')`
        ).bind(telegramId, data.username || null, data.first_name || null, data.photo_url || null).run();

        const userRow = await env.DB.prepare(`SELECT session_version FROM users WHERE telegram_id = ?`)
          .bind(telegramId).first();

        const token = await createSessionToken(telegramId, userRow.session_version, env.SESSION_SECRET);

        return json({
          token,
          user: {
            id: telegramId,
            username: data.username || null,
            first_name: data.first_name || null,
            photo_url: data.photo_url || null,
          },
        });
      }

      // ---- Всё, что ниже, требует авторизации ----
      const telegramId = await getAuthedTelegramId(request, env);

      if (pathname === "/api/me" && request.method === "GET") {
        if (!telegramId) return json({ error: "Не авторизован" }, 401);
        const user = await env.DB.prepare(
          `SELECT telegram_id as id, username, first_name, photo_url FROM users WHERE telegram_id = ?`
        ).bind(telegramId).first();
        if (!user) return json({ error: "Пользователь не найден" }, 404);
        return json({ user });
      }

      if (pathname === "/api/logout" && request.method === "POST") {
        if (!telegramId) return json({ error: "Не авторизован" }, 401);
        await env.DB.prepare(`UPDATE users SET session_version = session_version + 1 WHERE telegram_id = ?`)
          .bind(telegramId).run();
        return json({ ok: true });
      }

      if (pathname === "/api/projects" && request.method === "GET") {
        if (!telegramId) return json({ error: "Не авторизован" }, 401);
        const { results } = await env.DB.prepare(
          `SELECT id, name, updated_at FROM projects WHERE telegram_id = ? ORDER BY updated_at DESC`
        ).bind(telegramId).all();
        return json({ projects: results });
      }

      if (pathname === "/api/projects" && request.method === "POST") {
        if (!telegramId) return json({ error: "Не авторизован" }, 401);
        const body = await request.json();
        if (!body.name || !body.data) return json({ error: "Нужны поля name и data" }, 400);
        const res = await env.DB.prepare(
          `INSERT INTO projects (telegram_id, name, data, updated_at) VALUES (?, ?, ?, datetime('now'))`
        ).bind(telegramId, body.name, JSON.stringify(body.data)).run();
        return json({ id: res.meta.last_row_id });
      }

      const projectMatch = pathname.match(/^\/api\/projects\/(\d+)$/);
      if (projectMatch) {
        if (!telegramId) return json({ error: "Не авторизован" }, 401);
        const projectId = projectMatch[1];

        if (request.method === "GET") {
          const row = await env.DB.prepare(
            `SELECT id, name, data, updated_at FROM projects WHERE id = ? AND telegram_id = ?`
          ).bind(projectId, telegramId).first();
          if (!row) return json({ error: "Проект не найден" }, 404);
          return json({ id: row.id, name: row.name, data: JSON.parse(row.data), updated_at: row.updated_at });
        }

        if (request.method === "PUT") {
          const existing = await env.DB.prepare(`SELECT id FROM projects WHERE id = ? AND telegram_id = ?`)
            .bind(projectId, telegramId).first();
          if (!existing) return json({ error: "Проект не найден" }, 404);

          const body = await request.json();
          await env.DB.prepare(
            `UPDATE projects SET
               name = COALESCE(?, name),
               data = COALESCE(?, data),
               updated_at = datetime('now')
             WHERE id = ? AND telegram_id = ?`
          ).bind(body.name || null, body.data ? JSON.stringify(body.data) : null, projectId, telegramId).run();
          return json({ ok: true });
        }

        if (request.method === "DELETE") {
          await env.DB.prepare(`DELETE FROM projects WHERE id = ? AND telegram_id = ?`)
            .bind(projectId, telegramId).run();
          return json({ ok: true });
        }
      }

      return json({ error: "Маршрут не найден" }, 404);
    } catch (err) {
      return json({ error: "Внутренняя ошибка сервера", details: String(err && err.message ? err.message : err) }, 500);
    }
  },
};
