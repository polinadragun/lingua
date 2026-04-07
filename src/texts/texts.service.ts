import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    Logger,
    NotFoundException,
} from '@nestjs/common';
import { TextsRepository } from '../repositories/texts.repository';
import { UsersService } from '../users/users.service';
import { ObjectStorageService } from '../storage/object-storage.service';
import { Level } from '../domain/common/level';
import { TextLength } from '../domain/texts/text-length';
import { TextLanguage } from '../domain/texts/text-language';
import { TextTopic } from '../domain/texts/text-topic';
import { TextEntity } from '../domain/texts/text.entity';
import { CreateTextDto } from './dto/create-text.dto';

type CatalogQuery = {
    search?: string;
    level?: Level;
    topic?: TextTopic;
    length?: TextLength;
    language?: TextLanguage;
    authorEmail?: string;
    sortBy?: 'createdAt' | 'title' | 'level' | 'topic' | 'length';
    sortOrder?: 'asc' | 'desc';
    page?: number;
    limit?: number;
};

const AUDIO_MIME_TYPES = new Set([
    'audio/mpeg',
    'audio/mp3',
    'audio/wav',
    'audio/x-wav',
    'audio/ogg',
    'audio/webm',
    'audio/mp4',
    'audio/x-m4a',
]);

@Injectable()
export class TextsService {
    private readonly logger = new Logger(TextsService.name);

    constructor(
        private readonly textsRepository: TextsRepository,
        private readonly usersService: UsersService,
        private readonly objectStorage: ObjectStorageService,
    ) {}

    async getCatalog(query: CatalogQuery) {
        const page = query.page && query.page > 0 ? query.page : 1;
        const limit = query.limit && query.limit > 0 ? query.limit : 10;

        const params = {
            search: query.search,
            level: query.level,
            topic: query.topic,
            length: query.length,
            language: query.language,
            authorEmail: query.authorEmail,
            sortBy: query.sortBy ?? 'createdAt',
            sortOrder: query.sortOrder ?? 'desc',
            page,
            limit,
            isPublished: true,
        };

        const [items, total] = await Promise.all([
            this.textsRepository.findCatalog(params),
            this.textsRepository.countCatalog(params),
        ]);

        return {
            items: items.map((text) => ({
                id: text.id,
                slug: text.slug,
                title: text.title,
                description: text.description,
                level: text.level,
                language: text.language,
                topicKey: text.topic,
                topic: this.mapTopicLabel(text.topic),
                lengthKey: text.length,
                length: this.mapLengthLabel(text.length),
                audioUrl: text.audioUrl,
                authorEmail: text.authorEmail,
                createdAt: text.createdAt,
            })),
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit),
            },
            filters: {
                search: query.search ?? null,
                level: query.level ?? null,
                topic: query.topic ?? null,
                length: query.length ?? null,
                language: query.language ?? null,
                authorEmail: query.authorEmail ?? null,
            },
            sorting: {
                sortBy: params.sortBy,
                sortOrder: params.sortOrder,
            },
        };
    }

    async createText(dto: CreateTextDto) {
        const authorEmail = dto.authorEmail?.trim().toLowerCase();
        if (!authorEmail) {
            throw new BadRequestException('authorEmail is required');
        }
        await this.usersService.ensureUserByEmail(authorEmail);

        if (!dto.sentences?.length) {
            throw new BadRequestException('At least one sentence is required');
        }

        const slug = await this.generateUniqueSlug(dto.title);
        const topic = this.parseTopicInput(dto.topic);
        const level = this.parseLevelInput(dto.level);
        const length = dto.length
            ? this.parseLengthInput(dto.length)
            : this.inferLengthFromSentenceCount(dto.sentences.length);
        const language = dto.language
            ? this.parseLanguageInput(dto.language)
            : 'en';

        const description =
            dto.description?.trim() ||
            dto.sentences[0].text.trim().slice(0, 2000) ||
            dto.title.trim();

        const text = await this.textsRepository.createTextFull({
            slug,
            title: dto.title.trim(),
            description,
            level,
            topic,
            length,
            language,
            authorEmail,
            audioUrl: null,
            sentences: dto.sentences.map((s) => {
                const start = Number(s.start);
                const end = Number(s.end);
                const safeEnd = end > start ? end : start + 0.01;
                return {
                    orderIndex: s.orderIndex,
                    content: s.text.trim(),
                    startSeconds: start,
                    endSeconds: safeEnd,
                };
            }),
            words: dto.words.map((w) => ({
                key: w.key.trim().toLowerCase(),
                displayWord: w.word.trim(),
                translation: w.translation.trim(),
                transcription: w.transcription.trim(),
                example: w.example.trim(),
            })),
            questions: (dto.questions ?? []).map((q) => ({
                orderIndex: q.orderIndex,
                question: q.question.trim(),
                answer: q.answer.trim(),
            })),
        });

        return this.toDetailPayload(text);
    }

    async uploadAudioForSlug(
        slug: string,
        authorEmail: string | undefined,
        file: Express.Multer.File | undefined,
    ) {
        if (!authorEmail?.trim()) {
            throw new BadRequestException('authorEmail is required');
        }
        if (!file?.buffer?.length) {
            throw new BadRequestException('Audio file is required');
        }
        if (!AUDIO_MIME_TYPES.has(file.mimetype)) {
            throw new BadRequestException(`Unsupported audio type: ${file.mimetype}`);
        }

        const text = await this.textsRepository.findBySlug(slug);
        if (!text || !text.isPublished) {
            throw new NotFoundException('Text not found');
        }
        if (!text.authorEmail) {
            throw new ForbiddenException('This text cannot have audio attached');
        }
        if (text.authorEmail.trim().toLowerCase() !== authorEmail.trim().toLowerCase()) {
            throw new ForbiddenException('Author email does not match this text');
        }

        const audioUrl = await this.objectStorage.uploadPublicAudio({
            textId: text.id,
            buffer: file.buffer,
            originalName: file.originalname,
            mimeType: file.mimetype,
        });

        await this.textsRepository.updateText({
            id: text.id,
            audioUrl,
        });

        const updated = await this.textsRepository.findDetailedBySlug(slug);
        if (!updated) {
            throw new NotFoundException('Text not found');
        }

        return this.toDetailPayload(updated);
    }

    async getTextBySlug(slug: string) {
        const text = await this.textsRepository.findDetailedBySlug(slug);

        if (!text || !text.isPublished) {
            throw new NotFoundException('Text not found');
        }

        const url = text.audioUrl;
        this.logger.log(
            `GET text detail slug="${slug}" audioUrl=${url ? `set (${url.slice(0, 72)}${url.length > 72 ? '…' : ''})` : 'none'}`,
        );

        return this.toDetailPayload(text);
    }

    private toDetailPayload(text: TextEntity) {
        return {
            id: text.id,
            slug: text.slug,
            title: text.title,
            description: text.description,
            level: text.level,
            language: text.language,
            topicKey: text.topic,
            topic: this.mapTopicLabel(text.topic),
            lengthKey: text.length,
            length: this.mapLengthLabel(text.length),
            audioUrl: text.audioUrl,
            authorEmail: text.authorEmail,

            sentences: text.sentences.map((sentence) => ({
                id: sentence.id,
                orderIndex: sentence.orderIndex,
                text: sentence.content,
                start: sentence.startSeconds,
                end: sentence.endSeconds,
            })),

            words: Object.fromEntries(
                text.words.map((word) => [
                    word.key,
                    {
                        id: word.id,
                        word: word.displayWord,
                        translation: word.translation,
                        transcription: word.transcription,
                        example: word.example,
                    },
                ]),
            ),

            questions: text.questions.map((question) => ({
                id: question.id,
                orderIndex: question.orderIndex,
                question: question.question,
                answer: question.answer,
            })),

            mlAnnotationDraft: {
                textId: text.id,
                slug: text.slug,
                status: 'pending',
                sentenceAnnotations: text.sentences.map((sentence) => ({
                    sentenceId: sentence.id,
                    orderIndex: sentence.orderIndex,
                    labels: [],
                    notes: null,
                })),
                wordAnnotations: text.words.map((word) => ({
                    wordId: word.id,
                    key: word.key,
                    labels: [],
                    difficulty: null,
                    notes: null,
                })),
                questionAnnotations: text.questions.map((question) => ({
                    questionId: question.id,
                    orderIndex: question.orderIndex,
                    labels: [],
                    notes: null,
                })),
            },
        };
    }

    private async generateUniqueSlug(title: string): Promise<string> {
        const base = this.slugifyTitle(title);
        let candidate = base;
        let n = 0;
        while (n < 50) {
            const existing = await this.textsRepository.findBySlug(candidate);
            if (!existing) {
                return candidate;
            }
            n += 1;
            candidate = `${base}-${n}`;
        }
        throw new BadRequestException('Could not allocate unique slug');
    }

    private slugifyTitle(title: string): string {
        const s = title
            .toLowerCase()
            .normalize('NFKD')
            .replace(/[\u0300-\u036f]/g, '')
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .slice(0, 80);
        return s || 'text';
    }

    private parseTopicInput(raw: string): TextTopic {
        const key = raw.trim().toLowerCase();
        const map: Record<string, TextTopic> = {
            society: 'society',
            travel: 'travel',
            technology: 'technology',
            general: 'technology',
            culture: 'society',
        };
        const topic = map[key];
        if (!topic) {
            throw new BadRequestException(`Invalid topic: ${raw}`);
        }
        return topic;
    }

    private parseLevelInput(raw: string): Level {
        const allowed: Level[] = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];
        const v = raw.trim().toUpperCase() as Level;
        if (!allowed.includes(v)) {
            throw new BadRequestException(`Invalid level: ${raw}`);
        }
        return v;
    }

    private parseLengthInput(raw: string): TextLength {
        const key = raw.trim().toLowerCase();
        const map: Record<string, TextLength> = {
            short: 'short',
            medium: 'medium',
            long: 'long',
        };
        const length = map[key];
        if (!length) {
            throw new BadRequestException(`Invalid length: ${raw}`);
        }
        return length;
    }

    private parseLanguageInput(raw: string): TextLanguage {
        const key = raw.trim().toLowerCase();
        const allowed: TextLanguage[] = ['en', 'ch', 'fr', 'it', 'jp'];
        if (!allowed.includes(key as TextLanguage)) {
            throw new BadRequestException(`Invalid language: ${raw}`);
        }
        return key as TextLanguage;
    }

    private inferLengthFromSentenceCount(n: number): TextLength {
        if (n <= 4) return 'short';
        if (n <= 8) return 'medium';
        return 'long';
    }

    private mapTopicLabel(topic: TextTopic): string {
        const map: Record<TextTopic, string> = {
            society: 'Society',
            travel: 'Travel',
            technology: 'Technology',
        };

        return map[topic];
    }

    private mapLengthLabel(length: TextLength): string {
        const map: Record<TextLength, string> = {
            short: 'Short',
            medium: 'Medium',
            long: 'Long',
        };

        return map[length];
    }
}
