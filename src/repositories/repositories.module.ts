import { Module } from '@nestjs/common';
import { DbModule } from '../db/db.module';
import { AuthTokensRepository } from './auth-tokens.repository';
import { TextsRepository } from './texts.repository';
import { UserLibraryRepository } from './user-library.repository';
import { UsersRepository } from './users.repository';

@Module({
    imports: [DbModule],
    providers: [
        UsersRepository,
        AuthTokensRepository,
        TextsRepository,
        UserLibraryRepository,
    ],
    exports: [
        UsersRepository,
        AuthTokensRepository,
        TextsRepository,
        UserLibraryRepository,
    ],
})
export class RepositoriesModule {}