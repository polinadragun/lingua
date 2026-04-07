import { Module } from '@nestjs/common';
import { RepositoriesModule } from '../repositories/repositories.module';
import { UsersModule } from '../users/users.module';
import { AuthModule } from '../auth/auth.module';
import { ObjectStorageService } from '../storage/object-storage.service';
import { TextsService } from './texts.service';
import { TextsController } from './texts.controller';

@Module({
    imports: [RepositoriesModule, UsersModule, AuthModule],
    providers: [TextsService, ObjectStorageService],
    controllers: [TextsController],
    exports: [TextsService],
})
export class TextsModule {}