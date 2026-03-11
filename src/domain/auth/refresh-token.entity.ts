type RefreshTokenProps = {
    id: string;
    userId: string;
    tokenHash: string;
    expiresAt: Date;
    revokedAt: Date | null;
    createdAt: Date;
};

export class RefreshToken {
    private constructor(private readonly props: RefreshTokenProps) {}

    static reconstitute(props: RefreshTokenProps) {
        return new RefreshToken(props);
    }

    get id() {
        return this.props.id;
    }

    get userId() {
        return this.props.userId;
    }

    get tokenHash() {
        return this.props.tokenHash;
    }

    get expiresAt() {
        return this.props.expiresAt;
    }

    get revokedAt() {
        return this.props.revokedAt;
    }

    get createdAt() {
        return this.props.createdAt;
    }

    isRevoked(now = new Date()) {
        return this.props.revokedAt !== null || this.props.expiresAt <= now;
    }

    revoke(at = new Date()) {
        return new RefreshToken({
            ...this.props,
            revokedAt: at,
        });
    }
}