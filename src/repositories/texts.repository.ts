import { Inject, Injectable } from '@nestjs/common';
import { and, asc, desc, eq, ilike, or, sql, type SQL } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE_DB } from '../db/db.module';
import {
    textQuestions,
    textSentences,
    textWords,
    texts,
} from '../db/schema';
import { Level } from '../domain/common/level';
import { TextLength } from '../domain/texts/text-length';
import { TextLanguage } from '../domain/texts/text-language';
import { TextTopic } from '../domain/texts/text-topic';
import { TextEntity } from '../domain/texts/text.entity';
import { TextQuestion } from '../domain/texts/text-question.entity';
import { TextSentence } from '../domain/texts/text-sentence.entity';
import { TextWord } from '../domain/texts/text-word.entity';
import { TextsMapper } from './mappers/texts.mapper';

type FindCatalogParams = {
    search?: string;
    level?: Level;
    topic?: TextTopic;
    length?: TextLength;
    language?: TextLanguage;
    authorEmail?: string;
    isPublished?: boolean;
    sortBy?: 'createdAt' | 'title' | 'level' | 'topic' | 'length';
    sortOrder?: 'asc' | 'desc';
    page?: number;
    limit?: number;
};

@Injectable()
export class TextsRepository {
    constructor(@Inject(DRIZZLE_DB) private readonly db: NodePgDatabase) {}

    private buildCatalogConditions(params: FindCatalogParams = {}): SQL<unknown>[] {
        const conditions: SQL<unknown>[] = [];

        if (params.search?.trim()) {
            const pattern = `%${params.search.trim()}%`;

            const searchCondition = or(
                ilike(texts.title, pattern),
                ilike(sql<string>`${texts.topic}::text`, pattern),
            );

            if (searchCondition) {
                conditions.push(searchCondition);
            }
        }

        if (params.level) {
            conditions.push(eq(texts.level, params.level));
        }

        if (params.topic) {
            conditions.push(eq(texts.topic, params.topic));
        }

        if (params.length) {
            conditions.push(eq(texts.length, params.length));
        }

        if (params.language) {
            conditions.push(eq(texts.language, params.language));
        }

        if (params.authorEmail?.trim()) {
            conditions.push(eq(texts.authorEmail, params.authorEmail.trim()));
        }

        if (typeof params.isPublished === 'boolean') {
            conditions.push(eq(texts.isPublished, params.isPublished));
        }

        return conditions;
    }

    async findCatalog(params: FindCatalogParams = {}): Promise<TextEntity[]> {
        const conditions = this.buildCatalogConditions(params);

        const page = params.page && params.page > 0 ? params.page : 1;
        const limit = params.limit && params.limit > 0 ? params.limit : 10;
        const offset = (page - 1) * limit;

        const sortBy = params.sortBy ?? 'createdAt';
        const sortOrder = params.sortOrder ?? 'desc';

        const sortColumnMap = {
            createdAt: texts.createdAt,
            title: texts.title,
            level: texts.level,
            topic: texts.topic,
            length: texts.length,
        };

        const sortColumn = sortColumnMap[sortBy];
        const orderBy = sortOrder === 'asc' ? asc(sortColumn) : desc(sortColumn);

        const rows = await this.db
            .select()
            .from(texts)
            .where(conditions.length ? and(...conditions) : undefined)
            .orderBy(orderBy)
            .limit(limit)
            .offset(offset);

        return rows.map((row) => TextsMapper.toTextDomain({ text: row }));
    }

    async countCatalog(params: FindCatalogParams = {}): Promise<number> {
        const conditions = this.buildCatalogConditions(params);

        const rows = await this.db
            .select({ count: sql<number>`count(*)::int` })
            .from(texts)
            .where(conditions.length ? and(...conditions) : undefined);

        return rows[0]?.count ?? 0;
    }

    async findById(id: string): Promise<TextEntity | null> {
        const rows = await this.db.select().from(texts).where(eq(texts.id, id)).limit(1);
        return rows[0] ? TextsMapper.toTextDomain({ text: rows[0] }) : null;
    }

    async findBySlug(slug: string): Promise<TextEntity | null> {
        const rows = await this.db.select().from(texts).where(eq(texts.slug, slug)).limit(1);
        return rows[0] ? TextsMapper.toTextDomain({ text: rows[0] }) : null;
    }

    async findDetailedBySlug(slug: string): Promise<TextEntity | null> {
        const textRows = await this.db.select().from(texts).where(eq(texts.slug, slug)).limit(1);
        const textRow = textRows[0];

        if (!textRow) {
            return null;
        }

        const [sentenceRows, wordRows, questionRows] = await Promise.all([
            this.db
                .select()
                .from(textSentences)
                .where(eq(textSentences.textId, textRow.id))
                .orderBy(asc(textSentences.orderIndex)),
            this.db
                .select()
                .from(textWords)
                .where(eq(textWords.textId, textRow.id))
                .orderBy(asc(textWords.displayWord)),
            this.db
                .select()
                .from(textQuestions)
                .where(eq(textQuestions.textId, textRow.id))
                .orderBy(asc(textQuestions.orderIndex)),
        ]);

        return TextsMapper.toTextDomain({
            text: textRow,
            sentences: sentenceRows,
            words: wordRows,
            questions: questionRows,
        });
    }

    async createText(params: {
        slug: string;
        title: string;
        description: string;
        level: Level;
        topic: TextTopic;
        length: TextLength;
        language: TextLanguage;
        audioUrl?: string | null;
        authorEmail?: string | null;
        isPublished?: boolean;
    }): Promise<TextEntity> {
        const rows = await this.db
            .insert(texts)
            .values({
                slug: params.slug,
                title: params.title,
                description: params.description,
                level: params.level,
                topic: params.topic,
                length: params.length,
                language: params.language,
                audioUrl: params.audioUrl ?? null,
                authorEmail: params.authorEmail ?? null,
                isPublished: params.isPublished ?? true,
            })
            .returning();

        return TextsMapper.toTextDomain({ text: rows[0] });
    }

    async createTextFull(params: {
        slug: string;
        title: string;
        description: string;
        level: Level;
        topic: TextTopic;
        length: TextLength;
        language: TextLanguage;
        authorEmail?: string | null;
        audioUrl?: string | null;
        sentences: Array<{
            orderIndex: number;
            content: string;
            startSeconds: number;
            endSeconds: number;
        }>;
        words: Array<{
            key: string;
            displayWord: string;
            translation: string;
            transcription: string;
            example: string;
        }>;
        questions: Array<{
            orderIndex: number;
            question: string;
            answer: string;
        }>;
    }): Promise<TextEntity> {
        await this.db.transaction(async (tx) => {
            const inserted = await tx
                .insert(texts)
                .values({
                    slug: params.slug,
                    title: params.title,
                    description: params.description,
                    level: params.level,
                    topic: params.topic,
                    length: params.length,
                    language: params.language,
                    audioUrl: params.audioUrl ?? null,
                    authorEmail: params.authorEmail ?? null,
                    isPublished: true,
                })
                .returning();

            const textId = inserted[0].id;

            if (params.sentences.length) {
                await tx.insert(textSentences).values(
                    params.sentences.map((item) => ({
                        textId,
                        orderIndex: item.orderIndex,
                        content: item.content,
                        startSeconds: item.startSeconds,
                        endSeconds: item.endSeconds,
                    })),
                );
            }

            if (params.words.length) {
                await tx.insert(textWords).values(
                    params.words.map((item) => ({
                        textId,
                        key: item.key,
                        displayWord: item.displayWord,
                        translation: item.translation,
                        transcription: item.transcription,
                        example: item.example,
                    })),
                );
            }

            if (params.questions.length) {
                await tx.insert(textQuestions).values(
                    params.questions.map((item) => ({
                        textId,
                        orderIndex: item.orderIndex,
                        question: item.question,
                        answer: item.answer,
                    })),
                );
            }
        });

        const detailed = await this.findDetailedBySlug(params.slug);
        if (!detailed) {
            throw new Error('Failed to load created text');
        }

        return detailed;
    }

    async updateText(params: {
        id: string;
        slug?: string;
        title?: string;
        description?: string;
        level?: Level;
        topic?: TextTopic;
        length?: TextLength;
        language?: TextLanguage;
        audioUrl?: string | null;
        isPublished?: boolean;
    }): Promise<TextEntity | null> {
        const rows = await this.db
            .update(texts)
            .set({
                ...(params.slug !== undefined ? { slug: params.slug } : {}),
                ...(params.title !== undefined ? { title: params.title } : {}),
                ...(params.description !== undefined ? { description: params.description } : {}),
                ...(params.level !== undefined ? { level: params.level } : {}),
                ...(params.topic !== undefined ? { topic: params.topic } : {}),
                ...(params.length !== undefined ? { length: params.length } : {}),
                ...(params.language !== undefined ? { language: params.language } : {}),
                ...(params.audioUrl !== undefined ? { audioUrl: params.audioUrl } : {}),
                ...(params.isPublished !== undefined ? { isPublished: params.isPublished } : {}),
                updatedAt: new Date(),
            })
            .where(eq(texts.id, params.id))
            .returning();

        return rows[0] ? TextsMapper.toTextDomain({ text: rows[0] }) : null;
    }

    async replaceSentences(textId: string, items: Array<{
        orderIndex: number;
        content: string;
        startSeconds: number;
        endSeconds: number;
    }>): Promise<TextSentence[]> {
        await this.db.delete(textSentences).where(eq(textSentences.textId, textId));

        if (!items.length) {
            return [];
        }

        const rows = await this.db
            .insert(textSentences)
            .values(
                items.map((item) => ({
                    textId,
                    orderIndex: item.orderIndex,
                    content: item.content,
                    startSeconds: item.startSeconds,
                    endSeconds: item.endSeconds,
                })),
            )
            .returning();

        return rows.map((row) => TextsMapper.toSentenceDomain(row));
    }

    async replaceWords(textId: string, items: Array<{
        key: string;
        displayWord: string;
        translation: string;
        transcription: string;
        example: string;
    }>): Promise<TextWord[]> {
        await this.db.delete(textWords).where(eq(textWords.textId, textId));

        if (!items.length) {
            return [];
        }

        const rows = await this.db
            .insert(textWords)
            .values(
                items.map((item) => ({
                    textId,
                    key: item.key,
                    displayWord: item.displayWord,
                    translation: item.translation,
                    transcription: item.transcription,
                    example: item.example,
                })),
            )
            .returning();

        return rows.map((row) => TextsMapper.toWordDomain(row));
    }

    async replaceQuestions(textId: string, items: Array<{
        orderIndex: number;
        question: string;
        answer: string;
    }>): Promise<TextQuestion[]> {
        await this.db.delete(textQuestions).where(eq(textQuestions.textId, textId));

        if (!items.length) {
            return [];
        }

        const rows = await this.db
            .insert(textQuestions)
            .values(
                items.map((item) => ({
                    textId,
                    orderIndex: item.orderIndex,
                    question: item.question,
                    answer: item.answer,
                })),
            )
            .returning();

        return rows.map((row) => TextsMapper.toQuestionDomain(row));
    }

    async countPublished(): Promise<number> {
        const rows = await this.db
            .select({ count: sql<number>`count(*)::int` })
            .from(texts)
            .where(eq(texts.isPublished, true));

        return rows[0]?.count ?? 0;
    }
}