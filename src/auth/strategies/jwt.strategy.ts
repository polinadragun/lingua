import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { DEFAULT_ACCESS_COOKIE } from '../auth.constants';
import type { JwtPayload } from '../types/jwt-payload';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(private readonly config: ConfigService) {
        const accessCookie = config.get<string>('COOKIE_ACCESS_NAME') ?? DEFAULT_ACCESS_COOKIE;
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([
                (req: Request) =>
                    req?.cookies?.[accessCookie] ? String(req.cookies[accessCookie]) : null,
                ExtractJwt.fromAuthHeaderAsBearerToken(),
            ]),
            ignoreExpiration: false,
            secretOrKey: config.get<string>('JWT_SECRET') ?? 'dev-jwt-secret-change-me',
        });
    }

    validate(payload: JwtPayload): JwtPayload {
        return payload;
    }
}
