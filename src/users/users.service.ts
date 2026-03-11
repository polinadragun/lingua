import { Injectable } from '@nestjs/common';
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
}