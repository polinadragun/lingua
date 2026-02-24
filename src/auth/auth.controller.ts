import { Body, Controller, Get, Post, Req, Res, UseGuards, UnauthorizedException } from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from './guard';
import { CurrentUser } from './decorator';

@Controller('auth')
export class AuthController {
    constructor(private auth: AuthService) {}

    private setRefreshCookie(res: Response, token: string) {
        res.cookie('refresh_token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: false,
            path: '/auth',
        });
    }

    @Post('register')
    register(@Body() dto: RegisterDto) {
        return this.auth.register(dto);
    }

    @Post('login')
    async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
        const { session, refreshToken } = await this.auth.login(dto);
        this.setRefreshCookie(res, refreshToken);
        return session;
    }

    @Post('refresh')
    async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const rt = req.cookies?.refresh_token;
        if (!rt) throw new UnauthorizedException('No refresh cookie');

        const { session, refreshToken } = await this.auth.refresh(rt);
        this.setRefreshCookie(res, refreshToken);
        return session;
    }

    @Post('logout')
    async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        const rt = req.cookies?.refresh_token;
        if (rt) await this.auth.logout(rt);
        res.clearCookie('refresh_token', { path: '/auth' });
        return { ok: true };
    }

}