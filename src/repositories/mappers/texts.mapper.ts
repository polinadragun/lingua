import { InferSelectModel } from 'drizzle-orm';
import { textQuestions, textSentences, textWords, texts } from '../../db/schema';
import { TextEntity } from '../../domain/texts/text.entity';
import { TextQuestion } from '../../domain/texts/text-question.entity';
import { TextSentence } from '../../domain/texts/text-sentence.entity';
import { TextWord } from '../../domain/texts/text-word.entity';

type TextRow = InferSelectModel<typeof texts>;
type TextSentenceRow = InferSelectModel<typeof textSentences>;
type TextWordRow = InferSelectModel<typeof textWords>;
type TextQuestionRow = InferSelectModel<typeof textQuestions>;

export class TextsMapper {
    static toSentenceDomain(row: TextSentenceRow): TextSentence {
        return TextSentence.reconstitute({
            id: row.id,
            textId: row.textId,
            orderIndex: row.orderIndex,
            content: row.content,
            startSeconds: row.startSeconds,
            endSeconds: row.endSeconds,
        });
    }

    static toWordDomain(row: TextWordRow): TextWord {
        return TextWord.reconstitute({
            id: row.id,
            textId: row.textId,
            key: row.key,
            displayWord: row.displayWord,
            translation: row.translation,
            transcription: row.transcription,
            example: row.example,
            createdAt: row.createdAt,
        });
    }

    static toQuestionDomain(row: TextQuestionRow): TextQuestion {
        return TextQuestion.reconstitute({
            id: row.id,
            textId: row.textId,
            orderIndex: row.orderIndex,
            question: row.question,
            answer: row.answer,
        });
    }

    static toTextDomain(params: {
        text: TextRow;
        sentences?: TextSentenceRow[];
        words?: TextWordRow[];
        questions?: TextQuestionRow[];
    }): TextEntity {
        return TextEntity.reconstitute({
            id: params.text.id,
            slug: params.text.slug,
            title: params.text.title,
            description: params.text.description,
            level: params.text.level,
            topic: params.text.topic,
            length: params.text.length,
            language: params.text.language,
            audioUrl: params.text.audioUrl ?? null,
            authorEmail: params.text.authorEmail ?? null,
            isPublished: params.text.isPublished,
            createdAt: params.text.createdAt,
            updatedAt: params.text.updatedAt,
            sentences: (params.sentences ?? []).map((row) => this.toSentenceDomain(row)),
            words: (params.words ?? []).map((row) => this.toWordDomain(row)),
            questions: (params.questions ?? []).map((row) => this.toQuestionDomain(row)),
        });
    }
}