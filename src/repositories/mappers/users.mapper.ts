import { InferSelectModel } from 'drizzle-orm';
import { users } from '../../db/schema';
import { User } from '../../users/user.entity';

type UserRow = InferSelectModel<typeof users>;

export class UsersMapper {
    static toDomain(row: UserRow): User {
        return User.reconstitute({
            id: row.id,
            email: row.email,
            passwordHash: row.passwordHash,
            level: row.level,
            createdAt: row.createdAt,
            updatedAt: row.updatedAt,
        });
    }
}