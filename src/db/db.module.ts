import { Global, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';

export const DRIZZLE_DB = Symbol('DRIZZLE_DB');

@Global()
@Module({
    imports: [ConfigModule],
    providers: [
        {
            provide: DRIZZLE_DB,
            inject: [ConfigService],
            useFactory: (config: ConfigService): NodePgDatabase => {
                const pool = new Pool({
                    connectionString: config.get<string>('DATABASE_URL'),
                });
                return drizzle(pool);
            },
        },
    ],
    exports: [DRIZZLE_DB],
})
export class DbModule {}