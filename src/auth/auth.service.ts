import { Inject, Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { DRIZZLE_DB } from '../db/db.module';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { refreshTokens } from '../db/schema';
import { and, eq, isNull } from 'drizzle-orm';
import type { SignOptions } from 'jsonwebtoken';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

export type AuthSession = { user: { email: string; level: string }; token: string };
type AccessPayload = { sub: string; email: string; level: string };

@Injectable()
export class AuthService {
    constructor(
        private users: UsersService,
        private jwt: JwtService,
        private config: ConfigService,
        @Inject(DRIZZLE_DB) private db: NodePgDatabase,
    ) {}

    private accessTtl(): SignOptions['expiresIn'] {
        return (this.config.get<string>('ACCESS_TOKEN_TTL') ?? '15m') as SignOptions['expiresIn'];
    }

    private refreshDays(): number {
        return Number(this.config.get<string>('REFRESH_TOKEN_TTL_DAYS') ?? '30');
    }

    private signAccess(user: { id: string; email: string; level: string }): string {
        const payload: AccessPayload = { sub: user.id, email: user.email, level: user.level };

        return this.jwt.sign(payload, {
            secret: this.config.get<string>('JWT_ACCESS_SECRET') as string,
            expiresIn: this.accessTtl(),
        });
    }

    private refreshExpiresAt(): Date {
        const d = new Date();
        d.setDate(d.getDate() + this.refreshDays());
        return d;
    }

    private generateRefreshToken(): string {
        return crypto.randomUUID() + crypto.randomUUID() + crypto.randomUUID();
    }

    async register(dto: RegisterDto): Promise<AuthSession> {
        const existing = await this.users.findByEmail(dto.email);
        if (existing) throw new ConflictException('Email already in use');

        const passwordHash = await bcrypt.hash(dto.password, 10);
        const user = await this.users.create(dto.email, passwordHash);

        const token = this.signAccess(user);
        return { user: this.users.toPublicUser(user), token };
    }

    async login(dto: LoginDto): Promise<{ session: AuthSession; refreshToken: string }> {
        const user = await this.users.findByEmail(dto.email);
        if (!user) throw new UnauthorizedException('Invalid credentials');

        const ok = await bcrypt.compare(dto.password, user.passwordHash);
        if (!ok) throw new UnauthorizedException('Invalid credentials');

        const token = this.signAccess(user);

        const refreshTokenValue = this.generateRefreshToken();
        const tokenHash = await bcrypt.hash(refreshTokenValue, 10);

        await this.db.insert(refreshTokens).values({
            userId: user.id,
            tokenHash,
            expiresAt: this.refreshExpiresAt(),
        });

        return {
            session: { user: this.users.toPublicUser(user), token },
            refreshToken: refreshTokenValue,
        };
    }

    async refresh(oldRefreshToken: string): Promise<{ session: AuthSession; refreshToken: string }> {
        const now = new Date();

        const candidates = await this.db
            .select()
            .from(refreshTokens)
            .where(isNull(refreshTokens.revokedAt));

        const active = candidates.filter((t) => t.expiresAt > now);

        let matched: (typeof active)[number] | null = null;
        for (const t of active) {
            if (await bcrypt.compare(oldRefreshToken, t.tokenHash)) {
                matched = t;
                break;
            }
        }
        if (!matched) throw new UnauthorizedException('Invalid refresh token');

        const user = await this.users.findById(matched.userId);
        if (!user) throw new UnauthorizedException('User not found');

        await this.db
            .update(refreshTokens)
            .set({ revokedAt: new Date() })
            .where(eq(refreshTokens.id, matched.id));

        const newRefreshToken = this.generateRefreshToken();
        const newHash = await bcrypt.hash(newRefreshToken, 10);

        await this.db.insert(refreshTokens).values({
            userId: user.id,
            tokenHash: newHash,
            expiresAt: this.refreshExpiresAt(),
        });

        const token = this.signAccess(user);

        return {
            session: { user: this.users.toPublicUser(user), token },
            refreshToken: newRefreshToken,
        };
    }

    async logout(refreshTokenValue: string): Promise<void> {
        const candidates = await this.db.select().from(refreshTokens).where(isNull(refreshTokens.revokedAt));

        for (const t of candidates) {
            if (await bcrypt.compare(refreshTokenValue, t.tokenHash)) {
                await this.db
                    .update(refreshTokens)
                    .set({ revokedAt: new Date() })
                    .where(eq(refreshTokens.id, t.id));
                break;
            }
        }
    }
}