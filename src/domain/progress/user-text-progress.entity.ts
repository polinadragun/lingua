import { TextProgressStatus } from './text-progress-status';

type UserTextProgressProps = {
    id: string;
    userId: string;
    textId: string;
    status: TextProgressStatus;
    progressPercent: number;
    lastSentenceIndex: number | null;
    startedAt: Date | null;
    completedAt: Date | null;
    lastOpenedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
};

export class UserTextProgress {
    private constructor(private readonly props: UserTextProgressProps) {}

    static create(props: UserTextProgressProps) {
        if (props.progressPercent < 0 || props.progressPercent > 100) {
            throw new Error('Progress percent must be between 0 and 100');
        }

        return new UserTextProgress(props);
    }

    static reconstitute(props: UserTextProgressProps) {
        return new UserTextProgress(props);
    }

    get id() {
        return this.props.id;
    }

    get userId() {
        return this.props.userId;
    }

    get textId() {
        return this.props.textId;
    }

    get status() {
        return this.props.status;
    }

    get progressPercent() {
        return this.props.progressPercent;
    }

    get lastSentenceIndex() {
        return this.props.lastSentenceIndex;
    }

    get startedAt() {
        return this.props.startedAt;
    }

    get completedAt() {
        return this.props.completedAt;
    }

    get lastOpenedAt() {
        return this.props.lastOpenedAt;
    }

    get createdAt() {
        return this.props.createdAt;
    }

    get updatedAt() {
        return this.props.updatedAt;
    }

    start(now = new Date()) {
        return new UserTextProgress({
            ...this.props,
            status: 'in_progress',
            startedAt: this.props.startedAt ?? now,
            lastOpenedAt: now,
            updatedAt: now,
        });
    }

    updateProgress(progressPercent: number, lastSentenceIndex: number | null, now = new Date()) {
        if (progressPercent < 0 || progressPercent > 100) {
            throw new Error('Progress percent must be between 0 and 100');
        }

        if (progressPercent === 100) {
            return new UserTextProgress({
                ...this.props,
                status: 'completed',
                progressPercent: 100,
                lastSentenceIndex,
                startedAt: this.props.startedAt ?? now,
                completedAt: now,
                lastOpenedAt: now,
                updatedAt: now,
            });
        }

        return new UserTextProgress({
            ...this.props,
            status: progressPercent > 0 ? 'in_progress' : this.props.status,
            progressPercent,
            lastSentenceIndex,
            startedAt: this.props.startedAt ?? (progressPercent > 0 ? now : null),
            lastOpenedAt: now,
            updatedAt: now,
        });
    }

    complete(now = new Date()) {
        return new UserTextProgress({
            ...this.props,
            status: 'completed',
            progressPercent: 100,
            completedAt: now,
            lastOpenedAt: now,
            startedAt: this.props.startedAt ?? now,
            updatedAt: now,
        });
    }
}