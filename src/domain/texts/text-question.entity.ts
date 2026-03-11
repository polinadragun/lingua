type TextQuestionProps = {
    id: string;
    textId: string;
    orderIndex: number;
    question: string;
    answer: string;
};

export class TextQuestion {
    private constructor(private readonly props: TextQuestionProps) {}

    static create(props: TextQuestionProps) {
        return new TextQuestion(props);
    }

    static reconstitute(props: TextQuestionProps) {
        return new TextQuestion(props);
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

    get question() {
        return this.props.question;
    }

    get answer() {
        return this.props.answer;
    }
}