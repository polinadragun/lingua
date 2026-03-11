type TextWordProps = {
    id: string;
    textId: string;
    key: string;
    displayWord: string;
    translation: string;
    transcription: string;
    example: string;
    createdAt: Date;
};

export class TextWord {
    private constructor(private readonly props: TextWordProps) {}

    static create(props: TextWordProps) {
        return new TextWord({
            ...props,
            key: props.key.trim().toLowerCase(),
        });
    }

    static reconstitute(props: TextWordProps) {
        return new TextWord(props);
    }

    get id() {
        return this.props.id;
    }

    get textId() {
        return this.props.textId;
    }

    get key() {
        return this.props.key;
    }

    get displayWord() {
        return this.props.displayWord;
    }

    get translation() {
        return this.props.translation;
    }

    get transcription() {
        return this.props.transcription;
    }

    get example() {
        return this.props.example;
    }

    get createdAt() {
        return this.props.createdAt;
    }
}