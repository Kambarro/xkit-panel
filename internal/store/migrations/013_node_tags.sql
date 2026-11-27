-- 013_node_tags.sql — теги нод + bulk (P1 #13, 3x-ui group tags).
-- УРОК: теги («быстрые/резерв/дешёвые») + массовые операции (удалить/отключить истёкшие).
ALTER TABLE nodes ADD COLUMN tags TEXT NOT NULL DEFAULT '';
