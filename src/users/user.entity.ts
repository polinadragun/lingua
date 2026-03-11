import { Level } from '../domain/common/level';

type UserProps = {
    id: string;
    email: string;
    passwordHash: string;
    level: Level;
    createdAt: Date;
    updatedAt: Date;
};

export class User {
    private constructor(private readonly props: UserProps) {}

    static create(params: {
        id: string;
        email: string;
        passwordHash: string;
        level?: Level;
        createdAt: Date;
        updatedAt: Date;
    }) {
        return new User({
            id: params.id,
            email: params.email,
            passwordHash: params.passwordHash,
            level: params.level ?? 'A1',
            createdAt: params.createdAt,
            updatedAt: params.updatedAt,
        });
    }

    static reconstitute(props: UserProps) {
        return new User(props);
    }

    get id() {
        return this.props.id;
    }

    get email() {
        return this.props.email;
    }

    get passwordHash() {
        return this.props.passwordHash;
    }

    get level() {
        return this.props.level;
    }

    get createdAt() {
        return this.props.createdAt;
    }

    get updatedAt() {
        return this.props.updatedAt;
    }

    changeLevel(level: Level) {
        return new User({
            ...this.props,
            level,
            updatedAt: new Date(),
        });
    }

    toPublic() {
        return {
            id: this.props.id,
            email: this.props.email,
            level: this.props.level,
        };
    }
}