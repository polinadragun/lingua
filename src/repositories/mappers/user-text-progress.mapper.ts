import { InferSelectModel } from 'drizzle-orm';
import { userTextProgress } from '../../db/schema';
import { UserTextProgress } from '../../domain/progress/user-text-progress.entity';

type UserTextProgressRow = InferSelectModel<typeof userTextProgress>;

export class UserTextProgressMapper {
    static toDomain(row: UserTextProgressRow) {
        return UserTextProgress.reconstitute({
            id: row.id,
            userId: row.userId,
            textId: row.textId,
            status: row.status,
            progressPercent: row.progressPercent,
            lastSentenceIndex: row.lastSentenceIndex ?? null,
            startedAt: row.startedAt ?? null,
            completedAt: row.completedAt ?? null,
            lastOpenedAt: row.lastOpenedAt ?? null,
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
        });
    }
}