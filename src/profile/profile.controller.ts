import {
    Body,
    Controller,
    Get,
    Patch,
    Query,
    BadRequestException,
    UseGuards,
} from '@nestjs/common';
import { ProfileService } from './profile.service';
import { UsersService } from '../users/users.service';
import { Level } from '../domain/common/level';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CurrentUser } from '../auth/decorators/current-user.decorator';
import type { JwtPayload } from '../auth/types/jwt-payload';

@Controller('profile')
@UseGuards(JwtAuthGuard)
export class ProfileController {
    constructor(
        private readonly profileService: ProfileService,
        private readonly usersService: UsersService,
    ) {}

    @Get()
    async getProfile(@CurrentUser() user: JwtPayload) {
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.getSummaryByEmail(user.email);
    }

    @Patch('level')
    async patchLevel(@Body() body: { level?: string }, @CurrentUser() user: JwtPayload) {
        const level = body.level?.trim();
        const allowed: Level[] = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];
        if (!level || !allowed.includes(level as Level)) {
            throw new BadRequestException('Invalid level');
        }
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.updateLevel(user.email, level as Level);
    }

    @Patch('favorites')
    async patchFavorite(@Body() body: { slug?: string }, @CurrentUser() user: JwtPayload) {
        const slug = body.slug?.trim();
        if (!slug) {
            throw new BadRequestException('slug is required');
        }
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.toggleFavorite(user.email, slug);
    }

    @Patch('texts-read')
    async patchTextRead(@Body() body: { slug?: string }, @CurrentUser() user: JwtPayload) {
        const slug = body.slug?.trim();
        if (!slug) {
            throw new BadRequestException('slug is required');
        }
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.toggleTextCompleted(user.email, slug);
    }

    @Patch('learned-words')
    async patchLearnedWord(
        @Body() body: { slug?: string; key?: string },
        @CurrentUser() user: JwtPayload,
    ) {
        const slug = body.slug?.trim();
        const key = body.key?.trim();
        if (!slug) {
            throw new BadRequestException('slug is required');
        }
        if (!key) {
            throw new BadRequestException('key is required');
        }
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.toggleLearnedWord(user.email, slug, key);
    }

    @Get('learned-words')
    async getLearnedWords(@CurrentUser() user: JwtPayload) {
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.getLearnedWords(user.email);
    }

    @Get('learned-word-keys')
    async getLearnedWordKeys(@Query('slug') slug: string | undefined, @CurrentUser() user: JwtPayload) {
        const s = slug?.trim();
        if (!s) {
            throw new BadRequestException('slug query is required');
        }
        await this.usersService.ensureUserByEmail(user.email);
        return this.profileService.getLearnedWordKeys(user.email, s);
    }
}
