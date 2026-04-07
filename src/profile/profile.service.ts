import { Injectable, NotFoundException } from '@nestjs/common';
import { UsersRepository } from '../repositories/users.repository';
import { UserLibraryRepository } from '../repositories/user-library.repository';
import { TextsRepository } from '../repositories/texts.repository';
import { Level } from '../domain/common/level';

export type ProfileSummaryDto = {
    userExists: boolean;
    level: string;
    textsRead: string[];
    learnedWords: number;
    favorites: string[];
};

export type LearnedWordDto = {
    textSlug: string;
    key: string;
    word: string;
    translation: string;
    transcription: string;
    example: string;
    learnedAt: Date;
};

@Injectable()
export class ProfileService {
    constructor(
        private readonly usersRepository: UsersRepository,
        private readonly userLibraryRepository: UserLibraryRepository,
        private readonly textsRepository: TextsRepository,
    ) {}

    async getSummaryByEmail(email: string): Promise<ProfileSummaryDto> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            return {
                userExists: false,
                level: 'A1',
                textsRead: [],
                learnedWords: 0,
                favorites: [],
            };
        }

        const [completed, favs, learnedWords] = await Promise.all([
            this.userLibraryRepository.findCompletedTextsByUserId(user.id),
            this.userLibraryRepository.findFavoritesByUserId(user.id),
            this.userLibraryRepository.countLearnedWordsByUserId(user.id),
        ]);

        return {
            userExists: true,
            level: user.level,
            textsRead: completed.map((t) => t.slug),
            learnedWords,
            favorites: favs.map((t) => t.slug),
        };
    }

    async updateLevel(email: string, level: Level): Promise<ProfileSummaryDto> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        await this.usersRepository.updateLevel(user.id, level);
        return this.getSummaryByEmail(normalized);
    }

    async toggleFavorite(email: string, slug: string): Promise<ProfileSummaryDto> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const text = await this.textsRepository.findBySlug(slug.trim());
        if (!text) {
            throw new NotFoundException('Text not found');
        }

        const isFav = await this.userLibraryRepository.isFavorite(user.id, text.id);
        if (isFav) {
            await this.userLibraryRepository.removeFavorite(user.id, text.id);
        } else {
            await this.userLibraryRepository.addFavorite(user.id, text.id);
        }

        return this.getSummaryByEmail(normalized);
    }

    async toggleTextCompleted(email: string, slug: string): Promise<ProfileSummaryDto> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const text = await this.textsRepository.findBySlug(slug.trim());
        if (!text) {
            throw new NotFoundException('Text not found');
        }

        const existing = await this.userLibraryRepository.findProgressByUserAndText(user.id, text.id);
        if (existing?.status === 'completed') {
            await this.userLibraryRepository.clearProgress(user.id, text.id);
        } else {
            const now = new Date();
            await this.userLibraryRepository.upsertProgress({
                userId: user.id,
                textId: text.id,
                status: 'completed',
                progressPercent: 100,
                startedAt: existing?.startedAt ?? now,
                completedAt: now,
                lastOpenedAt: now,
                lastSentenceIndex: existing?.lastSentenceIndex ?? null,
            });
        }

        return this.getSummaryByEmail(normalized);
    }

    async toggleLearnedWord(email: string, slug: string, key: string): Promise<ProfileSummaryDto> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            throw new NotFoundException('User not found');
        }

        const text = await this.textsRepository.findBySlug(slug.trim());
        if (!text) {
            throw new NotFoundException('Text not found');
        }

        const word = await this.userLibraryRepository.findWordByTextAndKey(text.id, key.trim().toLowerCase());
        if (!word) {
            throw new NotFoundException('Word not found');
        }

        const learned = await this.userLibraryRepository.isWordLearned(user.id, word.id);
        if (learned) {
            await this.userLibraryRepository.unmarkWordLearned(user.id, word.id);
        } else {
            await this.userLibraryRepository.markWordLearned(user.id, word.id);
        }

        return this.getSummaryByEmail(normalized);
    }

    async getLearnedWords(email: string): Promise<LearnedWordDto[]> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            throw new NotFoundException('User not found');
        }
        return this.userLibraryRepository.findAllLearnedWordsByUserId(user.id);
    }

    async getLearnedWordKeys(email: string, slug: string): Promise<string[]> {
        const normalized = email.trim().toLowerCase();
        const user = await this.usersRepository.findByEmail(normalized);
        if (!user) {
            throw new NotFoundException('User not found');
        }
        const text = await this.textsRepository.findBySlug(slug.trim());
        if (!text) {
            throw new NotFoundException('Text not found');
        }
        return this.userLibraryRepository.findLearnedWordKeysByUserAndText(user.id, text.id);
    }
}
