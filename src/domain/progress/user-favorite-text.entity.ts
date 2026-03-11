type UserFavoriteTextProps = {
    userId: string;
    textId: string;
    createdAt: Date;
};

export class UserFavoriteText {
    private constructor(private readonly props: UserFavoriteTextProps) {}

    static create(props: UserFavoriteTextProps) {
        return new UserFavoriteText(props);
    }

    static reconstitute(props: UserFavoriteTextProps) {
        return new UserFavoriteText(props);
    }

    get userId() {
        return this.props.userId;
    }

    get textId() {
        return this.props.textId;
    }

    get createdAt() {
        return this.props.createdAt;
    }
}