CREATE TYPE "public"."text_length" AS ENUM('short', 'medium', 'long');--> statement-breakpoint
CREATE TYPE "public"."text_progress_status" AS ENUM('not_started', 'in_progress', 'completed');--> statement-breakpoint
CREATE TYPE "public"."text_topic" AS ENUM('society', 'travel', 'technology');--> statement-breakpoint
CREATE TABLE "text_questions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"text_id" uuid NOT NULL,
	"order_index" integer NOT NULL,
	"question" text NOT NULL,
	"answer" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "text_sentences" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"text_id" uuid NOT NULL,
	"order_index" integer NOT NULL,
	"content" text NOT NULL,
	"start_seconds" real NOT NULL,
	"end_seconds" real NOT NULL,
	CONSTRAINT "text_sentences_valid_timeline_chk" CHECK ("text_sentences"."start_seconds" >= 0 AND "text_sentences"."end_seconds" > "text_sentences"."start_seconds")
);
--> statement-breakpoint
CREATE TABLE "text_words" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"text_id" uuid NOT NULL,
	"key" text NOT NULL,
	"display_word" text NOT NULL,
	"translation" text NOT NULL,
	"transcription" text NOT NULL,
	"example" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "texts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"level" "level" NOT NULL,
	"topic" text_topic NOT NULL,
	"length" text_length NOT NULL,
	"audio_url" text,
	"is_published" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_favorite_texts" (
	"user_id" uuid NOT NULL,
	"text_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_favorite_texts_user_id_text_id_pk" PRIMARY KEY("user_id","text_id")
);
--> statement-breakpoint
CREATE TABLE "user_learned_words" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"text_word_id" uuid NOT NULL,
	"learned_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_text_progress" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"text_id" uuid NOT NULL,
	"status" text_progress_status DEFAULT 'not_started' NOT NULL,
	"progress_percent" integer DEFAULT 0 NOT NULL,
	"last_sentence_index" integer,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"last_opened_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_text_progress_valid_progress_chk" CHECK ("user_text_progress"."progress_percent" >= 0 AND "user_text_progress"."progress_percent" <= 100)
);
--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_email_unique";--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "level" SET DEFAULT 'A1';--> statement-breakpoint
ALTER TABLE "text_questions" ADD CONSTRAINT "text_questions_text_id_texts_id_fk" FOREIGN KEY ("text_id") REFERENCES "public"."texts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "text_sentences" ADD CONSTRAINT "text_sentences_text_id_texts_id_fk" FOREIGN KEY ("text_id") REFERENCES "public"."texts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "text_words" ADD CONSTRAINT "text_words_text_id_texts_id_fk" FOREIGN KEY ("text_id") REFERENCES "public"."texts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_favorite_texts" ADD CONSTRAINT "user_favorite_texts_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_favorite_texts" ADD CONSTRAINT "user_favorite_texts_text_id_texts_id_fk" FOREIGN KEY ("text_id") REFERENCES "public"."texts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_learned_words" ADD CONSTRAINT "user_learned_words_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_learned_words" ADD CONSTRAINT "user_learned_words_text_word_id_text_words_id_fk" FOREIGN KEY ("text_word_id") REFERENCES "public"."text_words"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_text_progress" ADD CONSTRAINT "user_text_progress_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_text_progress" ADD CONSTRAINT "user_text_progress_text_id_texts_id_fk" FOREIGN KEY ("text_id") REFERENCES "public"."texts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "text_questions_text_id_order_index_uq" ON "text_questions" USING btree ("text_id","order_index");--> statement-breakpoint
CREATE INDEX "text_questions_text_id_idx" ON "text_questions" USING btree ("text_id");--> statement-breakpoint
CREATE UNIQUE INDEX "text_sentences_text_id_order_index_uq" ON "text_sentences" USING btree ("text_id","order_index");--> statement-breakpoint
CREATE INDEX "text_sentences_text_id_idx" ON "text_sentences" USING btree ("text_id");--> statement-breakpoint
CREATE UNIQUE INDEX "text_words_text_id_key_uq" ON "text_words" USING btree ("text_id","key");--> statement-breakpoint
CREATE INDEX "text_words_text_id_idx" ON "text_words" USING btree ("text_id");--> statement-breakpoint
CREATE UNIQUE INDEX "texts_slug_uq" ON "texts" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "texts_title_idx" ON "texts" USING btree ("title");--> statement-breakpoint
CREATE INDEX "texts_level_idx" ON "texts" USING btree ("level");--> statement-breakpoint
CREATE INDEX "texts_topic_idx" ON "texts" USING btree ("topic");--> statement-breakpoint
CREATE INDEX "texts_length_idx" ON "texts" USING btree ("length");--> statement-breakpoint
CREATE INDEX "texts_is_published_idx" ON "texts" USING btree ("is_published");--> statement-breakpoint
CREATE INDEX "texts_catalog_filter_idx" ON "texts" USING btree ("level","topic","length","is_published");--> statement-breakpoint
CREATE INDEX "user_favorite_texts_text_id_idx" ON "user_favorite_texts" USING btree ("text_id");--> statement-breakpoint
CREATE INDEX "user_favorite_texts_created_at_idx" ON "user_favorite_texts" USING btree ("created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "user_learned_words_user_id_text_word_id_uq" ON "user_learned_words" USING btree ("user_id","text_word_id");--> statement-breakpoint
CREATE INDEX "user_learned_words_user_id_idx" ON "user_learned_words" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "user_learned_words_text_word_id_idx" ON "user_learned_words" USING btree ("text_word_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_text_progress_user_id_text_id_uq" ON "user_text_progress" USING btree ("user_id","text_id");--> statement-breakpoint
CREATE INDEX "user_text_progress_user_id_idx" ON "user_text_progress" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "user_text_progress_text_id_idx" ON "user_text_progress" USING btree ("text_id");--> statement-breakpoint
CREATE INDEX "user_text_progress_status_idx" ON "user_text_progress" USING btree ("status");--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "refresh_tokens_expires_at_idx" ON "refresh_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "refresh_tokens_revoked_at_idx" ON "refresh_tokens" USING btree ("revoked_at");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_uq" ON "users" USING btree ("email");--> statement-breakpoint
CREATE INDEX "users_created_at_idx" ON "users" USING btree ("created_at");

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS texts_search_vector_idx
    ON texts
    USING gin (
    to_tsvector(
    'simple',
    coalesce(title, '') || ' ' || coalesce(description, '')
    )
    );

CREATE INDEX IF NOT EXISTS texts_title_trgm_idx
    ON texts
    USING gin (title gin_trgm_ops);

CREATE INDEX IF NOT EXISTS texts_description_trgm_idx
    ON texts
    USING gin (description gin_trgm_ops);