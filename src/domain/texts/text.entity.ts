import { Level } from '../common/level';
import { TextLength } from './text-length';
import { TextQuestion } from './text-question.entity';
import { TextSentence } from './text-sentence.entity';
import { TextTopic } from './text-topic';
import { TextWord } from './text-word.entity';

type TextProps = {
    id: string;
    slug: string;
    title: string;
    description: string;
    level: Level;
    topic: TextTopic;
    length: TextLength;
    audioUrl: string | null;
    isPublished: boolean;
    createdAt: Date;
    updatedAt: Date;
    sentences: TextSentence[];
    words: TextWord[];
    questions: TextQuestion[];
};

export class TextEntity {
    private constructor(private readonly props: TextProps) {}

    static create(props: TextProps) {
        return new TextEntity({
            ...props,
            slug: props.slug.trim().toLowerCase(),
        });
    }

    static reconstitute(props: TextProps) {
        return new TextEntity(props);
    }

    get id() {
        return this.props.id;
    }

    get slug() {
        return this.props.slug;
    }

    get title() {
        return this.props.title;
    }

    get description() {
        return this.props.description;
    }

    get level() {
        return this.props.level;
    }

    get topic() {
        return this.props.topic;
    }

    get length() {
        return this.props.length;
    }

    get audioUrl() {
        return this.props.audioUrl;
    }

    get isPublished() {
        return this.props.isPublished;
    }

    get createdAt() {
        return this.props.createdAt;
    }

    get updatedAt() {
        return this.props.updatedAt;
    }

    get sentences() {
        return [...this.props.sentences];
    }

    get words() {
        return [...this.props.words];
    }

    get questions() {
        return [...this.props.questions];
    }

    publish() {
        return new TextEntity({
            ...this.props,
            isPublished: true,
            updatedAt: new Date(),
        });
    }

    unpublish() {
        return new TextEntity({
            ...this.props,
            isPublished: false,
            updatedAt: new Date(),
        });
    }
}