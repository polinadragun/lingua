import {
    Body,
    Controller,
    Get,
    HttpCode,
    Param,
    Post,
    Query,
    UploadedFile,
    UseGuards,
    UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { TextsService } from './texts.service';
import { CreateTextDto } from './dto/create-text.dto';
import { Level } from '../domain/common/level';
import { TextTopic } from '../domain/texts/text-topic';
import { TextLength } from '../domain/texts/text-length';
import { TextLanguage } from '../domain/texts/text-language';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { JwtPayload } from '../auth/types/jwt-payload';

type RawCatalogQuery = {
    search?: string;
    level?: string;
    topic?: string;
    length?: string;
    language?: string;
    authorEmail?: string;
    sortBy?: string;
    sortOrder?: string;
    page?: string;
    limit?: string;
};

@Controller('texts')
export class TextsController {
    constructor(private readonly textsService: TextsService) {}

    @Post()
    @HttpCode(201)
    @UseGuards(JwtAuthGuard)
    create(@Body() dto: CreateTextDto, @CurrentUser() user: JwtPayload) {
        return this.textsService.createText({
            ...dto,
            authorEmail: user.email,
        });
    }

    @Post(':slug/audio')
    @HttpCode(200)
    @UseGuards(JwtAuthGuard)
    @UseInterceptors(
        FileInterceptor('file', {
            storage: memoryStorage(),
            limits: { fileSize: 50 * 1024 * 1024 },
        }),
    )
    uploadAudio(
        @Param('slug') slug: string,
        @UploadedFile() file: Express.Multer.File | undefined,
        @CurrentUser() user: JwtPayload,
    ) {
        return this.textsService.uploadAudioForSlug(slug, user.email, file);
    }

    @Get()
    getCatalog(@Query() query: RawCatalogQuery) {
        return this.textsService.getCatalog({
            search: query.search?.trim() || undefined,
            level: this.parseLevel(query.level),
            topic: this.parseTopic(query.topic),
            length: this.parseLength(query.length),
            language: this.parseLanguage(query.language),
            authorEmail: query.authorEmail?.trim() || undefined,
            sortBy: this.parseSortBy(query.sortBy),
            sortOrder: this.parseSortOrder(query.sortOrder),
            page: this.parsePositiveNumber(query.page, 1),
            limit: this.parsePositiveNumber(query.limit, 10),
        });
    }

    @Get(':slug')
    getBySlug(@Param('slug') slug: string) {
        return this.textsService.getTextBySlug(slug);
    }

    private parsePositiveNumber(value?: string, fallback = 1): number {
        const parsed = Number(value);
        if (!Number.isFinite(parsed) || parsed <= 0) {
            return fallback;
        }
        return Math.floor(parsed);
    }

    private parseLevel(value?: string): Level | undefined {
        const allowed: Level[] = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];
        if (!value) return undefined;
        return allowed.includes(value as Level) ? (value as Level) : undefined;
    }

    private parseTopic(value?: string): TextTopic | undefined {
        const allowed: TextTopic[] = ['society', 'travel', 'technology'];
        if (!value) return undefined;
        return allowed.includes(value as TextTopic) ? (value as TextTopic) : undefined;
    }

    private parseLength(value?: string): TextLength | undefined {
        const allowed: TextLength[] = ['short', 'medium', 'long'];
        if (!value) return undefined;
        return allowed.includes(value as TextLength) ? (value as TextLength) : undefined;
    }

    private parseLanguage(value?: string): TextLanguage | undefined {
        const allowed: TextLanguage[] = ['en', 'ch', 'fr', 'it', 'jp'];
        if (!value) return undefined;
        return allowed.includes(value as TextLanguage) ? (value as TextLanguage) : undefined;
    }

    private parseSortBy(value?: string):
        | 'createdAt'
        | 'title'
        | 'level'
        | 'topic'
        | 'length'
        | undefined {
        const allowed = ['createdAt', 'title', 'level', 'topic', 'length'] as const;
        if (!value) return undefined;
        return allowed.includes(value as (typeof allowed)[number])
            ? (value as (typeof allowed)[number])
            : undefined;
    }

    private parseSortOrder(value?: string): 'asc' | 'desc' | undefined {
        if (value === 'asc' || value === 'desc') {
            return value;
        }
        return undefined;
    }
}
