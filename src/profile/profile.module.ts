import { Module } from '@nestjs/common';
import { RepositoriesModule } from '../repositories/repositories.module';
import { UsersModule } from '../users/users.module';
import { AuthModule } from '../auth/auth.module';
import { ProfileService } from './profile.service';
import { ProfileController } from './profile.controller';

@Module({
    imports: [RepositoriesModule, UsersModule, AuthModule],
    providers: [ProfileService],
    controllers: [ProfileController],
    exports: [ProfileService],
})
export class ProfileModule {}
