-- Схема базы данных D1 для Neuro Grafic.
-- Выполните этот файл целиком во вкладке "Console" вашей D1-базы в панели Cloudflare.

CREATE TABLE IF NOT EXISTS users (
  telegram_id     TEXT PRIMARY KEY,
  username        TEXT,
  first_name      TEXT,
  photo_url       TEXT,
  session_version INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT DEFAULT (datetime('now')),
  updated_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS projects (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id TEXT NOT NULL REFERENCES users(telegram_id),
  name        TEXT NOT NULL,
  data        TEXT NOT NULL,
  created_at  TEXT DEFAULT (datetime('now')),
  updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_projects_telegram_id ON projects(telegram_id);
