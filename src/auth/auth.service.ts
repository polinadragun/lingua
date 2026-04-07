import {
    ConflictException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { createHash, randomBytes } from 'crypto';
import type { Request, Response } from 'express';
import ms from 'ms';
import type { StringValue } from 'ms';
import { AuthTokensRepository } from '../repositories/auth-tokens.repository';
import { UsersService } from '../users/users.service';
import { User } from '../users/user.entity';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { DEFAULT_ACCESS_COOKIE, DEFAULT_REFRESH_COOKIE } from './auth.constants';
import type { JwtPayload } from './types/jwt-payload';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService,
        private readonly config: ConfigService,
        private readonly authTokensRepository: AuthTokensRepository,
    ) {}

    async register(dto: AuthCredentialsDto, res: Response) {
        const email = dto.email.trim().toLowerCase();
        const existing = await this.usersService.findByEmail(email);
        if (existing) {
            throw new ConflictException('User already exists');
        }

        const passwordHash = await bcrypt.hash(dto.password, 10);
        const user = await this.usersService.create(email, passwordHash);

        return this.issueSession(user, res);
    }

    async login(dto: AuthCredentialsDto, res: Response) {
        const email = dto.email.trim().toLowerCase();
        const user = await this.usersService.findByEmail(email);
        if (!user) {
            throw new UnauthorizedException('Invalid email or password');
        }

        const ok = await bcrypt.compare(dto.password, user.passwordHash);
        if (!ok) {
            throw new UnauthorizedException('Invalid email or password');
        }

        return this.issueSession(user, res);
    }

    /**
     * Rotate refresh token and issue new access + refresh cookies.
     */
    async refresh(req: Request, res: Response) {
        const refreshName = this.getRefreshCookieName();
        const raw = req.cookies?.[refreshName];
        if (!raw || typeof raw !== 'string') {
            throw new UnauthorizedException('Missing refresh token');
        }

        const tokenHash = this.hashRefreshToken(raw);
        const record = await this.authTokensRepository.findActiveByTokenHash(tokenHash);
        if (!record) {
            this.clearCookies(res);
            throw new UnauthorizedException('Invalid refresh token');
        }

        await this.authTokensRepository.revokeById(record.id);

        const user = await this.usersService.findById(record.userId);
        if (!user) {
            this.clearCookies(res);
            throw new UnauthorizedException('User not found');
        }

        return this.issueSession(user, res);
    }

    async logout(_req: Request, res: Response, user: JwtPayload) {
        await this.authTokensRepository.revokeAllActiveByUserId(user.sub);
        this.clearCookies(res);
        return { ok: true };
    }

    getMe(user: JwtPayload) {
        return {
            user: {
                id: user.sub,
                email: user.email,
                level: user.level,
            },
        };
    }

    private async issueSession(user: User, res: Response) {
        await this.authTokensRepository.revokeAllActiveByUserId(user.id);

        const accessToken = await this.signAccessToken(user);
        const refreshRaw = randomBytes(32).toString('base64url');
        const tokenHash = this.hashRefreshToken(refreshRaw);
        const refreshMs = ms(this.getRefreshTtlString() as StringValue);
        const expiresAt = new Date(Date.now() + refreshMs);

        await this.authTokensRepository.create({
            userId: user.id,
            tokenHash,
            expiresAt,
        });

        this.setCookies(res, accessToken, refreshRaw);

        return {
            user: this.usersService.toPublicUser(user),
        };
    }

    private async signAccessToken(user: User): Promise<string> {
        const payload: JwtPayload = {
            sub: user.id,
            email: user.email,
            level: user.level,
        };

        return this.jwtService.signAsync(payload, {
            secret: this.getJwtSecret(),
            expiresIn: this.getAccessTtlString() as StringValue,
        });
    }

    private hashRefreshToken(raw: string): string {
        return createHash('sha256').update(raw, 'utf8').digest('hex');
    }

    private setCookies(res: Response, accessToken: string, refreshRaw: string) {
        const base = this.cookieBaseOptions();
        const accessMs = ms(this.getAccessTtlString() as StringValue);
        const refreshMs = ms(this.getRefreshTtlString() as StringValue);

        res.cookie(this.getAccessCookieName(), accessToken, {
            ...base,
            maxAge: accessMs,
        });

        res.cookie(this.getRefreshCookieName(), refreshRaw, {
            ...base,
            maxAge: refreshMs,
        });
    }

    private clearCookies(res: Response) {
        const base = this.cookieBaseOptions();
        res.clearCookie(this.getAccessCookieName(), base);
        res.clearCookie(this.getRefreshCookieName(), base);
    }

    private cookieBaseOptions() {
        const secure =
            this.config.get<string>('COOKIE_SECURE') === 'true' ||
            process.env.NODE_ENV === 'production';
        const sameSite = (this.config.get<string>('COOKIE_SAME_SITE') ?? 'lax') as 'lax' | 'strict' | 'none';
        return {
            httpOnly: true,
            secure,
            sameSite,
            path: '/',
        };
    }

    private getAccessCookieName(): string {
        return this.config.get<string>('COOKIE_ACCESS_NAME') ?? DEFAULT_ACCESS_COOKIE;
    }

    private getRefreshCookieName(): string {
        return this.config.get<string>('COOKIE_REFRESH_NAME') ?? DEFAULT_REFRESH_COOKIE;
    }

    private getJwtSecret(): string {
        return this.config.get<string>('JWT_SECRET') ?? 'dev-jwt-secret-change-me';
    }

    /** Short-lived access JWT (e.g. 15m). */
    private getAccessTtlString(): string {
        return this.config.get<string>('JWT_ACCESS_EXPIRES_IN') ?? '15m';
    }

    /** Refresh token TTL stored in DB + refresh cookie (e.g. 7d). */
    private getRefreshTtlString(): string {
        return this.config.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '7d';
    }
}
