DO $$ BEGIN
    CREATE TYPE text_language AS ENUM ('en', 'ch', 'fr', 'it', 'jp');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

ALTER TABLE "texts"
    ADD COLUMN IF NOT EXISTS "language" "text_language" NOT NULL DEFAULT 'en';

CREATE INDEX IF NOT EXISTS "texts_language_idx" ON "texts" USING btree ("language");

