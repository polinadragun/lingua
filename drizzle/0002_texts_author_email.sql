ALTER TABLE "texts" ADD COLUMN IF NOT EXISTS "author_email" text;
CREATE INDEX IF NOT EXISTS "texts_author_email_idx" ON "texts" ("author_email");
