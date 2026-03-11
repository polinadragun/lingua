import { Inject, Injectable } from '@nestjs/common';
import { and, eq, gt, isNull } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE_DB } from '../db/db.module';
import { refreshTokens } from '../db/schema';
import { RefreshToken } from '../domain/auth/refresh-token.entity';
import { AuthMapper } from './mappers/auth.mapper';

@Injectable()
export class AuthTokensRepository {
    constructor(@Inject(DRIZZLE_DB) private readonly db: NodePgDatabase) {}

    async create(params: {
        userId: string;
        tokenHash: string;
        expiresAt: Date;
    }): Promise<RefreshToken> {
        const rows = await this.db
            .insert(refreshTokens)
            .values({
                userId: params.userId,
                tokenHash: params.tokenHash,
                expiresAt: params.expiresAt,
            })
            .returning();

        return AuthMapper.toRefreshTokenDomain(rows[0]);
    }

    async findActiveCandidates(): Promise<RefreshToken[]> {
        const rows = await this.db
            .select()
            .from(refreshTokens)
            .where(
                and(
                    isNull(refreshTokens.revokedAt),
                    gt(refreshTokens.expiresAt, new Date()),
                ),
            );

        return rows.map((row) => AuthMapper.toRefreshTokenDomain(row));
    }

    async findActiveByUserId(userId: string): Promise<RefreshToken[]> {
        const rows = await this.db
            .select()
            .from(refreshTokens)
            .where(
                and(
                    eq(refreshTokens.userId, userId),
                    isNull(refreshTokens.revokedAt),
                    gt(refreshTokens.expiresAt, new Date()),
                ),
            );

        return rows.map((row) => AuthMapper.toRefreshTokenDomain(row));
    }

    async revokeById(id: string): Promise<void> {
        await this.db
            .update(refreshTokens)
            .set({ revokedAt: new Date() })
            .where(eq(refreshTokens.id, id));
    }

    async revokeAllActiveByUserId(userId: string): Promise<void> {
        await this.db
            .update(refreshTokens)
            .set({ revokedAt: new Date() })
            .where(
                and(
                    eq(refreshTokens.userId, userId),
                    isNull(refreshTokens.revokedAt),
                ),
            );
    }

    async deleteExpired(): Promise<void> {
        await this.db.delete(refreshTokens).where(
            and(
                isNull(refreshTokens.revokedAt),
                gt(refreshTokens.expiresAt, new Date()),
            ),
        );
    }
}