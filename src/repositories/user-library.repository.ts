import { Inject, Injectable } from '@nestjs/common';
import { and, asc, eq, sql } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE_DB } from '../db/db.module';
import {
    textWords,
    texts,
    userFavoriteTexts,
    userLearnedWords,
    userTextProgress,
} from '../db/schema';
import { UserFavoriteText } from '../domain/progress/user-favorite-text.entity';
import { UserLearnedWord } from '../domain/progress/user-learned-word.entity';
import { UserTextProgress } from '../domain/progress/user-text-progress.entity';
import { TextEntity } from '../domain/texts/text.entity';
import { TextsMapper } from './mappers/texts.mapper';
import { UserLibraryMapper } from './mappers/user-library.mapper';

@Injectable()
export class UserLibraryRepository {
    constructor(@Inject(DRIZZLE_DB) private readonly db: NodePgDatabase) {}

    async addFavorite(userId: string, textId: string): Promise<UserFavoriteText> {
        const rows = await this.db
            .insert(userFavoriteTexts)
            .values({ userId, textId })
            .onConflictDoNothing()
            .returning();

        if (rows[0]) {
            return UserLibraryMapper.toFavoriteDomain(rows[0]);
        }

        const existing = await this.db
            .select()
            .from(userFavoriteTexts)
            .where(and(eq(userFavoriteTexts.userId, userId), eq(userFavoriteTexts.textId, textId)))
            .limit(1);

        return UserLibraryMapper.toFavoriteDomain(existing[0]);
    }

    async removeFavorite(userId: string, textId: string): Promise<void> {
        await this.db
            .delete(userFavoriteTexts)
            .where(and(eq(userFavoriteTexts.userId, userId), eq(userFavoriteTexts.textId, textId)));
    }

    async isFavorite(userId: string, textId: string): Promise<boolean> {
        const rows = await this.db
            .select()
            .from(userFavoriteTexts)
            .where(and(eq(userFavoriteTexts.userId, userId), eq(userFavoriteTexts.textId, textId)))
            .limit(1);

        return Boolean(rows[0]);
    }

    async findFavoritesByUserId(userId: string): Promise<TextEntity[]> {
        const rows = await this.db
            .select({ text: texts })
            .from(userFavoriteTexts)
            .innerJoin(texts, eq(userFavoriteTexts.textId, texts.id))
            .where(eq(userFavoriteTexts.userId, userId))
            .orderBy(asc(userFavoriteTexts.createdAt));

        return rows.map((row) => TextsMapper.toTextDomain({ text: row.text }));
    }

    async findProgressByUserAndText(userId: string, textId: string): Promise<UserTextProgress | null> {
        const rows = await this.db
            .select()
            .from(userTextProgress)
            .where(and(eq(userTextProgress.userId, userId), eq(userTextProgress.textId, textId)))
            .limit(1);

        return rows[0] ? UserLibraryMapper.toProgressDomain(rows[0]) : null;
    }

    async upsertProgress(params: {
        userId: string;
        textId: string;
        status: 'not_started' | 'in_progress' | 'completed';
        progressPercent: number;
        lastSentenceIndex?: number | null;
        startedAt?: Date | null;
        completedAt?: Date | null;
        lastOpenedAt?: Date | null;
    }): Promise<UserTextProgress> {
        const existing = await this.findProgressByUserAndText(params.userId, params.textId);

        if (!existing) {
            const rows = await this.db
                .insert(userTextProgress)
                .values({
                    userId: params.userId,
                    textId: params.textId,
                    status: params.status,
                    progressPercent: params.progressPercent,
                    lastSentenceIndex: params.lastSentenceIndex ?? null,
                    startedAt: params.startedAt ?? null,
                    completedAt: params.completedAt ?? null,
                    lastOpenedAt: params.lastOpenedAt ?? null,
                })
                .returning();

            return UserLibraryMapper.toProgressDomain(rows[0]);
        }

        const rows = await this.db
            .update(userTextProgress)
            .set({
                status: params.status,
                progressPercent: params.progressPercent,
                lastSentenceIndex: params.lastSentenceIndex ?? null,
                startedAt: params.startedAt ?? null,
                completedAt: params.completedAt ?? null,
                lastOpenedAt: params.lastOpenedAt ?? null,
                updatedAt: new Date(),
            })
            .where(and(eq(userTextProgress.userId, params.userId), eq(userTextProgress.textId, params.textId)))
            .returning();

        return UserLibraryMapper.toProgressDomain(rows[0]);
    }

    async findCompletedTextsByUserId(userId: string): Promise<TextEntity[]> {
        const rows = await this.db
            .select({ text: texts })
            .from(userTextProgress)
            .innerJoin(texts, eq(userTextProgress.textId, texts.id))
            .where(and(eq(userTextProgress.userId, userId), eq(userTextProgress.status, 'completed')))
            .orderBy(asc(userTextProgress.completedAt));

        return rows.map((row) => TextsMapper.toTextDomain({ text: row.text }));
    }

    async countCompletedTextsByUserId(userId: string): Promise<number> {
        const rows = await this.db
            .select({ count: sql<number>`count(*)::int` })
            .from(userTextProgress)
            .where(and(eq(userTextProgress.userId, userId), eq(userTextProgress.status, 'completed')));

        return rows[0]?.count ?? 0;
    }

    async markWordLearned(userId: string, textWordId: string): Promise<UserLearnedWord> {
        const rows = await this.db
            .insert(userLearnedWords)
            .values({ userId, textWordId })
            .onConflictDoNothing()
            .returning();

        if (rows[0]) {
            return UserLibraryMapper.toLearnedWordDomain(rows[0]);
        }

        const existing = await this.db
            .select()
            .from(userLearnedWords)
            .where(and(eq(userLearnedWords.userId, userId), eq(userLearnedWords.textWordId, textWordId)))
            .limit(1);

        return UserLibraryMapper.toLearnedWordDomain(existing[0]);
    }

    async unmarkWordLearned(userId: string, textWordId: string): Promise<void> {
        await this.db
            .delete(userLearnedWords)
            .where(and(eq(userLearnedWords.userId, userId), eq(userLearnedWords.textWordId, textWordId)));
    }

    async countLearnedWordsByUserId(userId: string): Promise<number> {
        const rows = await this.db
            .select({ count: sql<number>`count(*)::int` })
            .from(userLearnedWords)
            .where(eq(userLearnedWords.userId, userId));

        return rows[0]?.count ?? 0;
    }

    async findLearnedWordsByUserAndText(userId: string, textId: string): Promise<UserLearnedWord[]> {
        const rows = await this.db
            .select({ learned: userLearnedWords })
            .from(userLearnedWords)
            .innerJoin(textWords, eq(userLearnedWords.textWordId, textWords.id))
            .where(and(eq(userLearnedWords.userId, userId), eq(textWords.textId, textId)));

        return rows.map((row) => UserLibraryMapper.toLearnedWordDomain(row.learned));
    }
}