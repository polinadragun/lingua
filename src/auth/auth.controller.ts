import {
    Body,
    Controller,
    Get,
    HttpCode,
    Post,
    Req,
    Res,
    UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import type { JwtPayload } from './types/jwt-payload';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    @HttpCode(201)
    register(@Body() dto: AuthCredentialsDto, @Res({ passthrough: true }) res: Response) {
        return this.authService.register(dto, res);
    }

    @Post('login')
    @HttpCode(200)
    login(@Body() dto: AuthCredentialsDto, @Res({ passthrough: true }) res: Response) {
        return this.authService.login(dto, res);
    }

    /** Issue new access + refresh cookies from refresh cookie. */
    @Post('refresh')
    @HttpCode(200)
    refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
        return this.authService.refresh(req, res);
    }

    @Get('session')
    @HttpCode(200)
    @UseGuards(JwtAuthGuard)
    session(@CurrentUser() user: JwtPayload) {
        return this.authService.getMe(user);
    }

    @Post('logout')
    @HttpCode(200)
    @UseGuards(JwtAuthGuard)
    logout(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
        @CurrentUser() user: JwtPayload,
    ) {
        return this.authService.logout(req, res, user);
    }
}
