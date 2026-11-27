-- 031: in_sub flag — protocol works but can be hidden from subscription links
ALTER TABLE inbounds ADD COLUMN in_sub INTEGER NOT NULL DEFAULT 1;
