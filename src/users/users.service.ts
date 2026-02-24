import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { DRIZZLE_DB } from '../db/db.module';
import { users } from '../db/schema';

export type Level = 'A1' | 'A2' | 'B1' | 'B2' | 'C1' | 'C2';

@Injectable()
export class UsersService {
    constructor(@Inject(DRIZZLE_DB) private db: NodePgDatabase) {}

    async findByEmail(email: string) {
        const rows = await this.db.select().from(users).where(eq(users.email, email)).limit(1);
        return rows[0] ?? null;
    }

    async findById(id: string) {
        const rows = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
        return rows[0] ?? null;
    }

    async create(email: string, passwordHash: string, level: Level = 'A1') {
        const rows = await this.db
            .insert(users)
            .values({ email, passwordHash, level })
            .returning();
        return rows[0];
    }

    toPublicUser(u: { email: string; level: Level }) {
        return { email: u.email, level: u.level };
    }
}