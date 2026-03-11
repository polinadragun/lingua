import { Inject, Injectable } from '@nestjs/common';
import { and, asc, eq, ilike, or, sql, type SQL } from 'drizzle-orm';
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
    isPublished?: boolean;
};

@Injectable()
export class TextsRepository {
    constructor(@Inject(DRIZZLE_DB) private readonly db: NodePgDatabase) {}

    async findCatalog(params: FindCatalogParams = {}): Promise<TextEntity[]> {
        const conditions: SQL<unknown>[] = [];

        if (params.search?.trim()) {
            const pattern = `%${params.search.trim()}%`;

            const searchCondition = or(
                ilike(texts.title, pattern),
                ilike(texts.description, pattern),
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

        if (typeof params.isPublished === 'boolean') {
            conditions.push(eq(texts.isPublished, params.isPublished));
        }

        const rows = await this.db
            .select()
            .from(texts)
            .where(conditions.length ? and(...conditions) : undefined)
            .orderBy(asc(texts.createdAt));

        return rows.map((row) => TextsMapper.toTextDomain({ text: row }));
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
        audioUrl?: string | null;
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
                audioUrl: params.audioUrl ?? null,
                isPublished: params.isPublished ?? true,
            })
            .returning();

        return TextsMapper.toTextDomain({ text: rows[0] });
    }

    async updateText(params: {
        id: string;
        slug?: string;
        title?: string;
        description?: string;
        level?: Level;
        topic?: TextTopic;
        length?: TextLength;
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