import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Level } from '../domain/common/level';
import { User } from './user.entity';
import { UsersRepository } from '../repositories/users.repository';

@Injectable()
export class UsersService {
    constructor(private readonly usersRepository: UsersRepository) {}

    findByEmail(email: string): Promise<User | null> {
        return this.usersRepository.findByEmail(email);
    }

    findById(id: string): Promise<User | null> {
        return this.usersRepository.findById(id);
    }

    create(email: string, passwordHash: string, level: Level = 'A1'): Promise<User> {
        return this.usersRepository.create({ email, passwordHash, level });
    }

    toPublicUser(user: User) {
        return {
            id: user.id,
            email: user.email,
            level: user.level,
        };
    }

    /** Creates a DB user row for mock-auth email so texts/profile can persist without real registration. */
    async ensureUserByEmail(email: string): Promise<User> {
        const normalized = email.trim().toLowerCase();
        const existing = await this.usersRepository.findByEmail(normalized);
        if (existing) {
            return existing;
        }
        const passwordHash = await bcrypt.hash(`dev-placeholder-${normalized}-${Date.now()}`, 10);
        return this.usersRepository.create({
            email: normalized,
            passwordHash,
            level: 'A1',
        });
    }
}