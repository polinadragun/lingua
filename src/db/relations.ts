import { relations } from 'drizzle-orm';
import {
    refreshTokens,
    textQuestions,
    textSentences,
    textWords,
    texts,
    userFavoriteTexts,
    userLearnedWords,
    userTextProgress,
    users,
} from './schema';

export const usersRelations = relations(users, ({ many }) => ({
    refreshTokens: many(refreshTokens),
    favoriteTexts: many(userFavoriteTexts),
    textProgress: many(userTextProgress),
    learnedWords: many(userLearnedWords),
}));

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
    user: one(users, {
        fields: [refreshTokens.userId],
        references: [users.id],
    }),
}));

export const textsRelations = relations(texts, ({ many }) => ({
    sentences: many(textSentences),
    words: many(textWords),
    questions: many(textQuestions),
    favoritedBy: many(userFavoriteTexts),
    progressEntries: many(userTextProgress),
}));

export const textSentencesRelations = relations(textSentences, ({ one }) => ({
    text: one(texts, {
        fields: [textSentences.textId],
        references: [texts.id],
    }),
}));

export const textWordsRelations = relations(textWords, ({ one, many }) => ({
    text: one(texts, {
        fields: [textWords.textId],
        references: [texts.id],
    }),
    learnedByUsers: many(userLearnedWords),
}));

export const textQuestionsRelations = relations(textQuestions, ({ one }) => ({
    text: one(texts, {
        fields: [textQuestions.textId],
        references: [texts.id],
    }),
}));

export const userFavoriteTextsRelations = relations(userFavoriteTexts, ({ one }) => ({
    user: one(users, {
        fields: [userFavoriteTexts.userId],
        references: [users.id],
    }),
    text: one(texts, {
        fields: [userFavoriteTexts.textId],
        references: [texts.id],
    }),
}));

export const userTextProgressRelations = relations(userTextProgress, ({ one }) => ({
    user: one(users, {
        fields: [userTextProgress.userId],
        references: [users.id],
    }),
    text: one(texts, {
        fields: [userTextProgress.textId],
        references: [texts.id],
    }),
}));

export const userLearnedWordsRelations = relations(userLearnedWords, ({ one }) => ({
    user: one(users, {
        fields: [userLearnedWords.userId],
        references: [users.id],
    }),
    textWord: one(textWords, {
        fields: [userLearnedWords.textWordId],
        references: [textWords.id],
    }),
}));