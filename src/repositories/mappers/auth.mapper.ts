import { InferSelectModel } from 'drizzle-orm';
import { refreshTokens } from '../../db/schema';
import { RefreshToken } from '../../domain/auth/refresh-token.entity';

type RefreshTokenRow = InferSelectModel<typeof refreshTokens>;

export class AuthMapper {
    static toRefreshTokenDomain(row: RefreshTokenRow): RefreshToken {
        return RefreshToken.reconstitute({
            id: row.id,
            userId: row.userId,
            tokenHash: row.tokenHash,
            expiresAt: row.expiresAt,
            revokedAt: row.revokedAt ?? null,
            createdAt: row.createdAt,
        });
    }
}