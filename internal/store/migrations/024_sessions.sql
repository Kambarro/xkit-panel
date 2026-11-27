-- 024_sessions.sql — сессии в БД (переживают рестарт панели).
-- УРОК (QA): сессии были in-memory → каждый деплой/рестарт выкидывал админа на логин.
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY,
 username TEXT NOT NULL,
 expires INTEGER NOT NULL
);