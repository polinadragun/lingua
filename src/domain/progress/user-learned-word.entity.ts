type UserLearnedWordProps = {
    id: string;
    userId: string;
    textWordId: string;
    learnedAt: Date;
};

export class UserLearnedWord {
    private constructor(private readonly props: UserLearnedWordProps) {}

    static create(props: UserLearnedWordProps) {
        return new UserLearnedWord(props);
    }

    static reconstitute(props: UserLearnedWordProps) {
        return new UserLearnedWord(props);
    }

    get id() {
        return this.props.id;
    }

    get userId() {
        return this.props.userId;
    }

    get textWordId() {
        return this.props.textWordId;
    }

    get learnedAt() {
        return this.props.learnedAt;
    }
}