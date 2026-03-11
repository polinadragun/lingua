import { InferSelectModel } from 'drizzle-orm';
import { userFavoriteTexts, userLearnedWords, userTextProgress } from '../../db/schema';
import { UserFavoriteText } from '../../domain/progress/user-favorite-text.entity';
import { UserLearnedWord } from '../../domain/progress/user-learned-word.entity';
import { UserTextProgress } from '../../domain/progress/user-text-progress.entity';

type UserFavoriteTextRow = InferSelectModel<typeof userFavoriteTexts>;
type UserLearnedWordRow = InferSelectModel<typeof userLearnedWords>;
type UserTextProgressRow = InferSelectModel<typeof userTextProgress>;

export class UserLibraryMapper {
    static toFavoriteDomain(row: UserFavoriteTextRow): UserFavoriteText {
        return UserFavoriteText.reconstitute({
            userId: row.userId,
            textId: row.textId,
            createdAt: row.createdAt,
        });
    }

    static toLearnedWordDomain(row: UserLearnedWordRow): UserLearnedWord {
        return UserLearnedWord.reconstitute({
            id: row.id,
            userId: row.userId,
            textWordId: row.textWordId,
            learnedAt: row.learnedAt,
        });
    }

    static toProgressDomain(row: UserTextProgressRow): UserTextProgress {
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