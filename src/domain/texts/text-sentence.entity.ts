type TextSentenceProps = {
    id: string;
    textId: string;
    orderIndex: number;
    content: string;
    startSeconds: number;
    endSeconds: number;
};

export class TextSentence {
    private constructor(private readonly props: TextSentenceProps) {}

    static create(props: TextSentenceProps) {
        if (props.startSeconds < 0) {
            throw new Error('Sentence start time must be non-negative');
        }

        if (props.endSeconds <= props.startSeconds) {
            throw new Error('Sentence end time must be greater than start time');
        }

        return new TextSentence(props);
    }

    static reconstitute(props: TextSentenceProps) {
        return new TextSentence(props);
    }

    get id() {
        return this.props.id;
    }

    get textId() {
        return this.props.textId;
    }

    get orderIndex() {
        return this.props.orderIndex;
    }

    get content() {
        return this.props.content;
    }

    get startSeconds() {
        return this.props.startSeconds;
    }

    get endSeconds() {
        return this.props.endSeconds;
    }
}