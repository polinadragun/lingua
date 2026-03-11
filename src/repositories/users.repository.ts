import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE_DB } from '../db/db.module';
import { users } from '../db/schema';
import { Level } from '../domain/common/level';
import { User } from '../users/user.entity';
import { UsersMapper } from './mappers/users.mapper';

@Injectable()
export class UsersRepository {
    constructor(@Inject(DRIZZLE_DB) private readonly db: NodePgDatabase) {}

    async findById(id: string): Promise<User | null> {
        const rows = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
        return rows[0] ? UsersMapper.toDomain(rows[0]) : null;
    }

    async findByEmail(email: string): Promise<User | null> {
        const rows = await this.db.select().from(users).where(eq(users.email, email)).limit(1);
        return rows[0] ? UsersMapper.toDomain(rows[0]) : null;
    }

    async create(params: {
        email: string;
        passwordHash: string;
        level?: Level;
    }): Promise<User> {
        const rows = await this.db
            .insert(users)
            .values({
                email: params.email,
                passwordHash: params.passwordHash,
                level: params.level ?? 'A1',
            })
            .returning();

        return UsersMapper.toDomain(rows[0]);
    }

    async updateLevel(id: string, level: Level): Promise<User | null> {
        const rows = await this.db
            .update(users)
            .set({
                level,
                updatedAt: new Date(),
            })
            .where(eq(users.id, id))
            .returning();

        return rows[0] ? UsersMapper.toDomain(rows[0]) : null;
    }
}