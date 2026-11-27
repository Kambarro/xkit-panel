-- 029_node_note.sql — заметка к ноде (произвольный текст владельца: хостер, тариф, контакт).
ALTER TABLE nodes ADD COLUMN note TEXT NOT NULL DEFAULT '';