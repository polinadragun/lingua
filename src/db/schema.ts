import {
    boolean,
    check,
    index,
    integer,
    pgEnum,
    pgTable,
    primaryKey,
    real,
    text,
    timestamp,
    uniqueIndex,
    uuid,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const levelEnum = pgEnum('level', ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']);
export const textTopicEnum = pgEnum('text_topic', ['society', 'travel', 'technology']);
export const textLengthEnum = pgEnum('text_length', ['short', 'medium', 'long']);
export const textLanguageEnum = pgEnum('text_language', ['en', 'ch', 'fr', 'it', 'jp']);
export const textProgressStatusEnum = pgEnum('text_progress_status', [
    'not_started',
    'in_progress',
    'completed',
]);

export const users = pgTable(
    'users',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        email: text('email').notNull(),
        passwordHash: text('password_hash').notNull(),
        level: levelEnum('level').notNull().default('A1'),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        emailUq: uniqueIndex('users_email_uq').on(t.email),
        createdAtIdx: index('users_created_at_idx').on(t.createdAt),
    }),
);

export const refreshTokens = pgTable(
    'refresh_tokens',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, { onDelete: 'cascade' }),
        tokenHash: text('token_hash').notNull(),
        expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
        revokedAt: timestamp('revoked_at', { withTimezone: true }),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        userIdIdx: index('refresh_tokens_user_id_idx').on(t.userId),
        expiresAtIdx: index('refresh_tokens_expires_at_idx').on(t.expiresAt),
        revokedAtIdx: index('refresh_tokens_revoked_at_idx').on(t.revokedAt),
    }),
);

export const texts = pgTable(
    'texts',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        slug: text('slug').notNull(),
        title: text('title').notNull(),
        description: text('description').notNull(),
        level: levelEnum('level').notNull(),
        topic: textTopicEnum('topic').notNull(),
        length: textLengthEnum('length').notNull(),
        language: textLanguageEnum('language').notNull().default('en'),
        audioUrl: text('audio_url'),
        /** Set for user-created texts (mock auth email); seeded texts leave null */
        authorEmail: text('author_email'),
        isPublished: boolean('is_published').notNull().default(true),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        slugUq: uniqueIndex('texts_slug_uq').on(t.slug),
        titleIdx: index('texts_title_idx').on(t.title),
        levelIdx: index('texts_level_idx').on(t.level),
        topicIdx: index('texts_topic_idx').on(t.topic),
        lengthIdx: index('texts_length_idx').on(t.length),
        languageIdx: index('texts_language_idx').on(t.language),
        publishedIdx: index('texts_is_published_idx').on(t.isPublished),
        authorEmailIdx: index('texts_author_email_idx').on(t.authorEmail),
        catalogFilterIdx: index('texts_catalog_filter_idx').on(t.level, t.topic, t.length, t.isPublished),
    }),
);

export const textSentences = pgTable(
    'text_sentences',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        textId: uuid('text_id')
            .notNull()
            .references(() => texts.id, { onDelete: 'cascade' }),
        orderIndex: integer('order_index').notNull(),
        content: text('content').notNull(),
        startSeconds: real('start_seconds').notNull(),
        endSeconds: real('end_seconds').notNull(),
    },
    (t) => ({
        textOrderUq: uniqueIndex('text_sentences_text_id_order_index_uq').on(t.textId, t.orderIndex),
        textIdIdx: index('text_sentences_text_id_idx').on(t.textId),
        validTimeline: check(
            'text_sentences_valid_timeline_chk',
            sql`${t.startSeconds} >= 0 AND ${t.endSeconds} > ${t.startSeconds}`,
        ),
    }),
);

export const textWords = pgTable(
    'text_words',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        textId: uuid('text_id')
            .notNull()
            .references(() => texts.id, { onDelete: 'cascade' }),
        key: text('key').notNull(),
        displayWord: text('display_word').notNull(),
        translation: text('translation').notNull(),
        transcription: text('transcription').notNull(),
        example: text('example').notNull(),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        textKeyUq: uniqueIndex('text_words_text_id_key_uq').on(t.textId, t.key),
        textIdIdx: index('text_words_text_id_idx').on(t.textId),
    }),
);

export const textQuestions = pgTable(
    'text_questions',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        textId: uuid('text_id')
            .notNull()
            .references(() => texts.id, { onDelete: 'cascade' }),
        orderIndex: integer('order_index').notNull(),
        question: text('question').notNull(),
        answer: text('answer').notNull(),
    },
    (t) => ({
        textOrderUq: uniqueIndex('text_questions_text_id_order_index_uq').on(t.textId, t.orderIndex),
        textIdIdx: index('text_questions_text_id_idx').on(t.textId),
    }),
);

export const userFavoriteTexts = pgTable(
    'user_favorite_texts',
    {
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, { onDelete: 'cascade' }),
        textId: uuid('text_id')
            .notNull()
            .references(() => texts.id, { onDelete: 'cascade' }),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        pk: primaryKey({ columns: [t.userId, t.textId] }),
        textIdIdx: index('user_favorite_texts_text_id_idx').on(t.textId),
        createdAtIdx: index('user_favorite_texts_created_at_idx').on(t.createdAt),
    }),
);

export const userTextProgress = pgTable(
    'user_text_progress',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, { onDelete: 'cascade' }),
        textId: uuid('text_id')
            .notNull()
            .references(() => texts.id, { onDelete: 'cascade' }),
        status: textProgressStatusEnum('status').notNull().default('not_started'),
        progressPercent: integer('progress_percent').notNull().default(0),
        lastSentenceIndex: integer('last_sentence_index'),
        startedAt: timestamp('started_at', { withTimezone: true }),
        completedAt: timestamp('completed_at', { withTimezone: true }),
        lastOpenedAt: timestamp('last_opened_at', { withTimezone: true }),
        createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
        updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        userTextUq: uniqueIndex('user_text_progress_user_id_text_id_uq').on(t.userId, t.textId),
        userIdIdx: index('user_text_progress_user_id_idx').on(t.userId),
        textIdIdx: index('user_text_progress_text_id_idx').on(t.textId),
        statusIdx: index('user_text_progress_status_idx').on(t.status),
        validProgress: check(
            'user_text_progress_valid_progress_chk',
            sql`${t.progressPercent} >= 0 AND ${t.progressPercent} <= 100`,
        ),
    }),
);

export const userLearnedWords = pgTable(
    'user_learned_words',
    {
        id: uuid('id').defaultRandom().primaryKey(),
        userId: uuid('user_id')
            .notNull()
            .references(() => users.id, { onDelete: 'cascade' }),
        textWordId: uuid('text_word_id')
            .notNull()
            .references(() => textWords.id, { onDelete: 'cascade' }),
        learnedAt: timestamp('learned_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => ({
        userWordUq: uniqueIndex('user_learned_words_user_id_text_word_id_uq').on(t.userId, t.textWordId),
        userIdIdx: index('user_learned_words_user_id_idx').on(t.userId),
        textWordIdIdx: index('user_learned_words_text_word_id_idx').on(t.textWordId),
    }),
);