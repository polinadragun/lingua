import 'dotenv/config';
import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { eq, inArray, like, or, sql } from 'drizzle-orm';

import {
    texts,
    textSentences,
    textWords,
    textQuestions,
} from '../db/schema';

type SeedText = {
    slug: string;
    title: string;
    description: string;
    level: 'A1' | 'A2' | 'B1' | 'B2' | 'C1' | 'C2';
    topic: 'society' | 'travel' | 'technology';
    length: 'short' | 'medium' | 'long';
    language: 'en' | 'ch' | 'fr' | 'it' | 'jp';
    audioUrl: string | null;
    isPublished: boolean;
    sentences: Array<{
        orderIndex: number;
        content: string;
        startSeconds: number;
        endSeconds: number;
    }>;
    words: Array<{
        key: string;
        displayWord: string;
        translation: string;
        transcription: string;
        example: string;
    }>;
    questions: Array<{
        orderIndex: number;
        question: string;
        answer: string;
    }>;
};

const seedTexts: SeedText[] = [
    {
        slug: 'life-in-a-modern-city',
        title: 'Life in a Modern City',
        description:
            'A reflective text about daily life, technology, and human interaction in a modern city.',
        level: 'B2',
        topic: 'society',
        length: 'medium',
        language: 'en',
        audioUrl: null,
        isPublished: true,
        sentences: [
            {
                orderIndex: 1,
                content:
                    'Living in a modern city offers countless opportunities for personal and professional growth.',
                startSeconds: 0,
                endSeconds: 5,
            },
            {
                orderIndex: 2,
                content:
                    'People are constantly surrounded by technology, information, and fast-paced lifestyles.',
                startSeconds: 6,
                endSeconds: 12,
            },
            {
                orderIndex: 3,
                content:
                    'However, this rapid rhythm of life can also be exhausting for many individuals.',
                startSeconds: 13,
                endSeconds: 18,
            },
            {
                orderIndex: 4,
                content:
                    'Moments of rest and quiet reflection become increasingly valuable in such an environment.',
                startSeconds: 19,
                endSeconds: 25,
            },
        ],
        words: [
            {
                key: 'opportunities',
                displayWord: 'opportunities',
                translation: 'возможности',
                transcription: '[ˌɒpəˈtjuːnɪtiz]',
                example: 'The city provides many job opportunities.',
            },
            {
                key: 'surrounded',
                displayWord: 'surrounded',
                translation: 'окружённый',
                transcription: '[səˈraʊndɪd]',
                example: 'She felt surrounded by people.',
            },
            {
                key: 'exhausting',
                displayWord: 'exhausting',
                translation: 'изнурительный',
                transcription: '[ɪɡˈzɔːstɪŋ]',
                example: 'The work schedule was exhausting.',
            },
            {
                key: 'reflection',
                displayWord: 'reflection',
                translation: 'размышление',
                transcription: '[rɪˈflekʃən]',
                example: 'Quiet reflection helps reduce stress.',
            },
        ],
        questions: [
            {
                orderIndex: 1,
                question: 'What does life in a modern city offer?',
                answer: 'It offers opportunities for personal and professional growth.',
            },
            {
                orderIndex: 2,
                question: 'Why do moments of rest become valuable?',
                answer: 'Because city life is fast-paced and can be exhausting.',
            },
        ],
    },
    {
        slug: 'traveling-alone',
        title: 'Traveling Alone',
        description:
            'A text about the challenges and benefits of solo travel.',
        level: 'B1',
        topic: 'travel',
        length: 'short',
        language: 'en',
        audioUrl: null,
        isPublished: true,
        sentences: [
            {
                orderIndex: 1,
                content:
                    'Traveling alone can be both exciting and challenging for many people.',
                startSeconds: 0,
                endSeconds: 4,
            },
            {
                orderIndex: 2,
                content:
                    'It gives travelers freedom to choose their own route, schedule, and activities.',
                startSeconds: 5,
                endSeconds: 10,
            },
            {
                orderIndex: 3,
                content:
                    'At the same time, solo travelers must solve problems independently and stay organized.',
                startSeconds: 11,
                endSeconds: 16,
            },
            {
                orderIndex: 4,
                content:
                    'Many people discover confidence and independence through this experience.',
                startSeconds: 17,
                endSeconds: 22,
            },
        ],
        words: [
            {
                key: 'challenging',
                displayWord: 'challenging',
                translation: 'сложный',
                transcription: '[ˈtʃælɪndʒɪŋ]',
                example: 'Learning a new language can be challenging.',
            },
            {
                key: 'freedom',
                displayWord: 'freedom',
                translation: 'свобода',
                transcription: '[ˈfriːdəm]',
                example: 'Travel gives people a sense of freedom.',
            },
            {
                key: 'independently',
                displayWord: 'independently',
                translation: 'самостоятельно',
                transcription: '[ˌɪndɪˈpendəntli]',
                example: 'She learned to work independently.',
            },
        ],
        questions: [
            {
                orderIndex: 1,
                question: 'What is one advantage of traveling alone?',
                answer: 'It gives freedom to choose your own plans.',
            },
            {
                orderIndex: 2,
                question: 'What do solo travelers often develop?',
                answer: 'They often develop confidence and independence.',
            },
        ],
    },
    {
        slug: 'technology-and-daily-life',
        title: 'Technology and Daily Life',
        description:
            'A text about how technology influences communication, work, and everyday routines.',
        level: 'B2',
        topic: 'technology',
        length: 'medium',
        language: 'en',
        audioUrl: null,
        isPublished: true,
        sentences: [
            {
                orderIndex: 1,
                content:
                    'Technology has become an essential part of daily life in the modern world.',
                startSeconds: 0,
                endSeconds: 5,
            },
            {
                orderIndex: 2,
                content:
                    'People use digital tools for communication, education, shopping, and entertainment.',
                startSeconds: 6,
                endSeconds: 11,
            },
            {
                orderIndex: 3,
                content:
                    'These tools save time, but they can also create dependence and distraction.',
                startSeconds: 12,
                endSeconds: 17,
            },
            {
                orderIndex: 4,
                content:
                    'A balanced approach helps people enjoy the benefits of innovation without losing focus.',
                startSeconds: 18,
                endSeconds: 24,
            },
        ],
        words: [
            {
                key: 'essential',
                displayWord: 'essential',
                translation: 'необходимый',
                transcription: '[ɪˈsenʃəl]',
                example: 'Water is essential for life.',
            },
            {
                key: 'dependence',
                displayWord: 'dependence',
                translation: 'зависимость',
                transcription: '[dɪˈpendəns]',
                example: 'Excessive phone use may lead to dependence.',
            },
            {
                key: 'innovation',
                displayWord: 'innovation',
                translation: 'инновация',
                transcription: '[ˌɪnəˈveɪʃən]',
                example: 'Innovation changes the way companies work.',
            },
        ],
        questions: [
            {
                orderIndex: 1,
                question: 'How do people use digital tools?',
                answer: 'They use them for communication, education, shopping, and entertainment.',
            },
            {
                orderIndex: 2,
                question: 'Why is balance important?',
                answer: 'Because technology gives benefits but may also cause distraction and dependence.',
            },
        ],
    },
];

function makeSeedPack(params: {
    level: SeedText['level'];
    count: number;
    language?: SeedText['language'];
}): SeedText[] {
    const topics: SeedText['topic'][] = ['society', 'travel', 'technology'];
    const lengths: SeedText['length'][] = ['short', 'medium', 'long'];

    const out: SeedText[] = [];
    for (let i = 1; i <= params.count; i += 1) {
        const topic = topics[(i - 1) % topics.length];
        const length = lengths[(i - 1) % lengths.length];
        const n = String(i).padStart(2, '0');
        const language = params.language ?? 'en';
        const slug = `seed-${language}-${params.level.toLowerCase()}-${n}-${topic}-${length}`;
        const topicLabel =
            language === 'ch'
                ? topic === 'society'
                    ? '社会'
                    : topic === 'travel'
                      ? '旅行'
                      : '科技'
                : language === 'fr'
                  ? topic === 'society'
                      ? 'societe'
                      : topic === 'travel'
                        ? 'voyage'
                        : 'technologie'
                  : language === 'it'
                    ? topic === 'society'
                        ? 'societa'
                        : topic === 'travel'
                          ? 'viaggio'
                          : 'tecnologia'
                    : topic;
        const lengthLabel =
            language === 'ch'
                ? length === 'short'
                    ? '短篇'
                    : length === 'medium'
                      ? '中篇'
                      : '长篇'
                : language === 'fr'
                  ? length === 'short'
                      ? 'court'
                      : length === 'medium'
                        ? 'moyen'
                        : 'long'
                  : language === 'it'
                    ? length === 'short'
                        ? 'breve'
                        : length === 'medium'
                          ? 'medio'
                          : 'lungo'
                    : length;

        const title =
            language === 'ch'
                ? `示例文本 ${params.level}-${n}（${topicLabel}，${lengthLabel}）`
                : language === 'fr'
                  ? `Texte exemple ${params.level}-${n} (${topicLabel}, ${lengthLabel})`
                  : language === 'it'
                    ? `Testo esempio ${params.level}-${n} (${topicLabel}, ${lengthLabel})`
                    : `Seed ${params.level} ${n} · ${topic} · ${length}`;
        const description =
            language === 'ch'
                ? `用于目录筛选测试的${params.level}级${topicLabel}文本。`
                : language === 'fr'
                  ? `Texte ${topicLabel} niveau ${params.level} pour verifier les filtres du catalogue.`
                  : language === 'it'
                    ? `Testo di livello ${params.level} sul tema ${topicLabel} per verificare i filtri del catalogo.`
                    : `Generated seed text (${params.level}, ${topic}, ${length}) for testing catalog filters.`;
        const line1 =
            language === 'ch'
                ? `这是一篇${params.level}级${topicLabel}主题的练习文本。`
                : language === 'fr'
                  ? `Voici un texte de niveau ${params.level} sur le theme ${topicLabel}.`
                  : language === 'it'
                    ? `Questo e un testo di livello ${params.level} sul tema ${topicLabel}.`
                    : `This is a ${params.level} ${topic} text created for testing filters.`;
        const line2 =
            language === 'ch'
                ? `文章长度为${lengthLabel}，内容围绕${topicLabel}展开。`
                : language === 'fr'
                  ? `Sa longueur est ${lengthLabel} et il traite principalement de ${topicLabel}.`
                  : language === 'it'
                    ? `La lunghezza del testo e ${lengthLabel} e l argomento principale e ${topicLabel}.`
                    : `It has a ${length} length label and a unique slug: ${slug}.`;
        const line3 =
            language === 'ch'
                ? `可以用这篇文章测试搜索，以及按主题和长度分组。`
                : language === 'fr'
                  ? `Vous pouvez l utiliser pour tester la recherche et les regroupements du catalogue.`
                  : language === 'it'
                    ? `Puoi usarlo per verificare la ricerca e i gruppi per tema e lunghezza.`
                    : `Use it to verify search and group pages by topic and length.`;

        out.push({
            slug,
            title,
            description,
            level: params.level,
            topic,
            length,
            language,
            audioUrl: null,
            isPublished: true,
            sentences: [
                {
                    orderIndex: 1,
                    content: line1,
                    startSeconds: 0,
                    endSeconds: 4,
                },
                {
                    orderIndex: 2,
                    content: line2,
                    startSeconds: 5,
                    endSeconds: 10,
                },
                {
                    orderIndex: 3,
                    content: line3,
                    startSeconds: 11,
                    endSeconds: 16,
                },
            ],
            words: [
                {
                    key: 'testing',
                    displayWord: 'testing',
                    translation: 'тестирование',
                    transcription: '[ˈtestɪŋ]',
                    example: 'Testing helps find issues early.',
                },
                {
                    key: 'filter',
                    displayWord: 'filter',
                    translation: 'фильтр',
                    transcription: '[ˈfɪltə]',
                    example: 'A filter shows only matching items.',
                },
                {
                    key: 'level',
                    displayWord: 'level',
                    translation: 'уровень',
                    transcription: '[ˈlevəl]',
                    example: 'The user level changes the catalog.',
                },
            ],
            questions: [
                {
                    orderIndex: 1,
                    question: 'What is this text for?',
                    answer: 'It is generated to test catalog filtering by level.',
                },
            ],
        });
    }
    return out;
}

const chTexts: SeedText[] = [
    {
        slug: 'ch-beijing-night-market',
        title: '北京夜市见闻',
        description: '一篇关于北京夜市与街头美食文化的中文短文。',
        level: 'A2',
        topic: 'travel',
        length: 'short',
        language: 'ch',
        audioUrl: null,
        isPublished: true,
        sentences: [
            { orderIndex: 1, content: '北京的夜市很热闹，游客和本地人都喜欢去。', startSeconds: 0, endSeconds: 4 },
            { orderIndex: 2, content: '你可以尝到烤串、饺子和很多甜点。', startSeconds: 5, endSeconds: 9 },
            { orderIndex: 3, content: '很多摊主会一边做菜一边聊天。', startSeconds: 10, endSeconds: 14 },
        ],
        words: [
            { key: '夜市', displayWord: '夜市', translation: 'night market', transcription: 'yeshi', example: '我们晚上去夜市。' },
            { key: '热闹', displayWord: '热闹', translation: 'lively', transcription: 'renao', example: '这里很热闹。' },
            { key: '摊主', displayWord: '摊主', translation: 'vendor', transcription: 'tanzhu', example: '摊主很热情。' },
        ],
        questions: [{ orderIndex: 1, question: '夜市里有什么吃的？', answer: '有烤串、饺子和甜点。' }],
    },
    {
        slug: 'ch-high-speed-train-day',
        title: '高铁上的一天',
        description: '一篇讲述家庭高铁出行体验的中文文章。',
        level: 'B1',
        topic: 'travel',
        length: 'medium',
        language: 'ch',
        audioUrl: null,
        isPublished: true,
        sentences: [
            { orderIndex: 1, content: '周末我们坐高铁从上海去杭州。', startSeconds: 0, endSeconds: 4 },
            { orderIndex: 2, content: '车厢很安静，大家都在看书或者休息。', startSeconds: 5, endSeconds: 9 },
            { orderIndex: 3, content: '两个小时后，我们就到了西湖附近。', startSeconds: 10, endSeconds: 14 },
            { orderIndex: 4, content: '高铁让短途旅行变得非常方便。', startSeconds: 15, endSeconds: 19 },
        ],
        words: [
            { key: '高铁', displayWord: '高铁', translation: 'high-speed train', transcription: 'gaotie', example: '高铁很准时。' },
            { key: '车厢', displayWord: '车厢', translation: 'carriage', transcription: 'chexiang', example: '车厢里很干净。' },
            { key: '方便', displayWord: '方便', translation: 'convenient', transcription: 'fangbian', example: '这个方法很方便。' },
        ],
        questions: [{ orderIndex: 1, question: '他们为什么喜欢坐高铁？', answer: '因为短途旅行很方便。' }],
    },
];

const frTexts: SeedText[] = [
    {
        slug: 'fr-un-cafe-a-lyon',
        title: 'Un cafe a Lyon',
        description: 'Un texte en francais sur les habitudes du matin dans un petit cafe lyonnais.',
        level: 'A2',
        topic: 'society',
        length: 'short',
        language: 'fr',
        audioUrl: null,
        isPublished: true,
        sentences: [
            { orderIndex: 1, content: 'Chaque matin, le cafe de la rue ouvre a sept heures.', startSeconds: 0, endSeconds: 4 },
            { orderIndex: 2, content: 'Les voisins viennent boire un cafe et lire le journal.', startSeconds: 5, endSeconds: 9 },
            { orderIndex: 3, content: 'Le serveur connait presque tous les clients.', startSeconds: 10, endSeconds: 14 },
        ],
        words: [
            { key: 'voisins', displayWord: 'voisins', translation: 'neighbors', transcription: '[vwazin]', example: 'Les voisins se saluent.' },
            { key: 'journal', displayWord: 'journal', translation: 'newspaper', transcription: '[ʒuʁnal]', example: 'Il lit le journal.' },
            { key: 'serveur', displayWord: 'serveur', translation: 'waiter', transcription: '[sɛʁvœʁ]', example: 'Le serveur est gentil.' },
        ],
        questions: [{ orderIndex: 1, question: 'Que font les voisins le matin ?', answer: 'Ils boivent un cafe et lisent le journal.' }],
    },
    {
        slug: 'fr-voyage-en-train-de-nuit',
        title: 'Voyage en train de nuit',
        description: 'Un texte en francais sur un voyage en train de nuit et les impressions de trajet.',
        level: 'B2',
        topic: 'travel',
        length: 'medium',
        language: 'fr',
        audioUrl: null,
        isPublished: true,
        sentences: [
            { orderIndex: 1, content: 'Nous avons choisi le train de nuit pour traverser le pays.', startSeconds: 0, endSeconds: 4 },
            { orderIndex: 2, content: 'Pendant le voyage, les paysages changeaient lentement derriere la fenetre.', startSeconds: 5, endSeconds: 9 },
            { orderIndex: 3, content: 'Le matin, nous sommes arrives reposés au centre-ville.', startSeconds: 10, endSeconds: 14 },
            { orderIndex: 4, content: 'Ce type de voyage est plus calme que l avion.', startSeconds: 15, endSeconds: 19 },
        ],
        words: [
            { key: 'paysages', displayWord: 'paysages', translation: 'landscapes', transcription: '[peizaʒ]', example: 'Les paysages etaient magnifiques.' },
            { key: 'fenetre', displayWord: 'fenetre', translation: 'window', transcription: '[fənɛtʁ]', example: 'Elle regarde par la fenetre.' },
            { key: 'calme', displayWord: 'calme', translation: 'calm', transcription: '[kalm]', example: 'Le trajet etait calme.' },
        ],
        questions: [{ orderIndex: 1, question: 'Pourquoi ont-ils choisi le train de nuit ?', answer: 'Parce que le voyage est plus calme.' }],
    },
];

const itTexts: SeedText[] = [
    {
        slug: 'it-mercato-del-sabato',
        title: 'Mercato del sabato',
        description: 'Un testo in italiano sul mercato del fine settimana e la vita di quartiere.',
        level: 'A2',
        topic: 'society',
        length: 'short',
        language: 'it',
        audioUrl: null,
        isPublished: true,
        sentences: [
            { orderIndex: 1, content: 'Ogni sabato la piazza si riempie di banchi colorati.', startSeconds: 0, endSeconds: 4 },
            { orderIndex: 2, content: 'Le famiglie comprano frutta, pane e formaggio fresco.', startSeconds: 5, endSeconds: 9 },
            { orderIndex: 3, content: 'Il mercato e anche un luogo per incontrare amici.', startSeconds: 10, endSeconds: 14 },
        ],
        words: [
            { key: 'piazza', displayWord: 'piazza', translation: 'square', transcription: '[ˈpjattsa]', example: 'Ci vediamo in piazza.' },
            { key: 'banchi', displayWord: 'banchi', translation: 'stalls', transcription: '[ˈbaŋki]', example: 'I banchi sono pieni.' },
            { key: 'fresco', displayWord: 'fresco', translation: 'fresh', transcription: '[ˈfresko]', example: 'Il pane e fresco.' },
        ],
        questions: [{ orderIndex: 1, question: 'Cosa comprano le famiglie?', answer: 'Frutta, pane e formaggio fresco.' }],
    },
    {
        slug: 'it-lavoro-remoto-a-milano',
        title: 'Lavoro remoto a Milano',
        description: 'Un testo in italiano sulle abitudini del lavoro remoto in una citta moderna.',
        level: 'B1',
        topic: 'technology',
        length: 'medium',
        language: 'it',
        audioUrl: null,
        isPublished: true,
        sentences: [
            { orderIndex: 1, content: 'Molti professionisti lavorano da casa tre giorni alla settimana.', startSeconds: 0, endSeconds: 4 },
            { orderIndex: 2, content: 'Usano piattaforme online per riunioni e gestione dei progetti.', startSeconds: 5, endSeconds: 9 },
            { orderIndex: 3, content: 'Il risparmio di tempo negli spostamenti migliora l equilibrio personale.', startSeconds: 10, endSeconds: 14 },
            { orderIndex: 4, content: 'Tuttavia, alcuni preferiscono incontrarsi in ufficio una volta a settimana.', startSeconds: 15, endSeconds: 19 },
        ],
        words: [
            { key: 'riunioni', displayWord: 'riunioni', translation: 'meetings', transcription: '[rjuˈnjoːni]', example: 'Le riunioni iniziano alle nove.' },
            { key: 'spostamenti', displayWord: 'spostamenti', translation: 'commutes', transcription: '[spostaˈmenti]', example: 'Gli spostamenti sono lunghi.' },
            { key: 'equilibrio', displayWord: 'equilibrio', translation: 'balance', transcription: '[ekwiˈliːbrjo]', example: 'Cerco equilibrio tra lavoro e vita.' },
        ],
        questions: [{ orderIndex: 1, question: 'Quale vantaggio principale cita il testo?', answer: 'Il risparmio di tempo negli spostamenti.' }],
    },
];

seedTexts.push(
    ...makeSeedPack({ level: 'A1', count: 10 }),
    ...makeSeedPack({ level: 'A2', count: 10 }),
    ...makeSeedPack({ level: 'B1', count: 10 }),
    ...makeSeedPack({ level: 'B2', count: 10 }),
    ...makeSeedPack({ level: 'C1', count: 10 }),
    ...makeSeedPack({ level: 'C2', count: 10 }),
    ...makeSeedPack({ level: 'A1', count: 4, language: 'ch' }),
    ...makeSeedPack({ level: 'B1', count: 4, language: 'ch' }),
    ...makeSeedPack({ level: 'C1', count: 4, language: 'ch' }),
    ...makeSeedPack({ level: 'A2', count: 4, language: 'fr' }),
    ...makeSeedPack({ level: 'B2', count: 4, language: 'fr' }),
    ...makeSeedPack({ level: 'C2', count: 4, language: 'fr' }),
    ...makeSeedPack({ level: 'A2', count: 4, language: 'it' }),
    ...makeSeedPack({ level: 'B1', count: 4, language: 'it' }),
    ...makeSeedPack({ level: 'C1', count: 4, language: 'it' }),
    ...chTexts,
    ...frTexts,
    ...itTexts,
);

const STATIC_SEED_SLUGS = [
    'life-in-a-modern-city',
    'traveling-alone',
    'technology-and-daily-life',
    'ch-beijing-night-market',
    'ch-high-speed-train-day',
    'fr-un-cafe-a-lyon',
    'fr-voyage-en-train-de-nuit',
    'it-mercato-del-sabato',
    'it-lavoro-remoto-a-milano',
];
async function main() {
    const databaseUrl = process.env.DATABASE_URL;

    if (!databaseUrl) {
        throw new Error('DATABASE_URL is not set');
    }

    const pool = new Pool({
        connectionString: databaseUrl,
    });

    const db = drizzle(pool);

    try {
        await db.execute(sql`DO $$ BEGIN CREATE TYPE text_language AS ENUM ('en','ch','fr','it','jp'); EXCEPTION WHEN duplicate_object THEN null; END $$;`);
        await db.execute(sql`ALTER TABLE texts ADD COLUMN IF NOT EXISTS language text_language NOT NULL DEFAULT 'en';`);
        await db.execute(sql`CREATE INDEX IF NOT EXISTS texts_language_idx ON texts(language);`);

        // Cleanup old seeded content so each run leaves only current seed set.
        await db
            .delete(texts)
            .where(
                or(
                    like(texts.slug, 'seed-%'),
                    inArray(texts.slug, STATIC_SEED_SLUGS),
                ),
            );

        for (const item of seedTexts) {
            const existing = await db
                .select()
                .from(texts)
                .where(eq(texts.slug, item.slug))
                .limit(1);

            let textId: string;

            if (existing[0]) {
                textId = existing[0].id;

                await db
                    .update(texts)
                    .set({
                        title: item.title,
                        description: item.description,
                        level: item.level,
                        topic: item.topic,
                        length: item.length,
                        language: item.language,
                        audioUrl: item.audioUrl,
                        isPublished: item.isPublished,
                        updatedAt: new Date(),
                    })
                    .where(eq(texts.id, textId));

                await db.delete(textSentences).where(eq(textSentences.textId, textId));
                await db.delete(textWords).where(eq(textWords.textId, textId));
                await db.delete(textQuestions).where(eq(textQuestions.textId, textId));
            } else {
                const inserted = await db
                    .insert(texts)
                    .values({
                        slug: item.slug,
                        title: item.title,
                        description: item.description,
                        level: item.level,
                        topic: item.topic,
                        length: item.length,
                        language: item.language,
                        audioUrl: item.audioUrl,
                        isPublished: item.isPublished,
                    })
                    .returning({ id: texts.id });

                textId = inserted[0].id;
            }

            if (item.sentences.length) {
                await db.insert(textSentences).values(
                    item.sentences.map((sentence) => ({
                        textId,
                        orderIndex: sentence.orderIndex,
                        content: sentence.content,
                        startSeconds: sentence.startSeconds,
                        endSeconds: sentence.endSeconds,
                    })),
                );
            }

            if (item.words.length) {
                await db.insert(textWords).values(
                    item.words.map((word) => ({
                        textId,
                        key: word.key,
                        displayWord: word.displayWord,
                        translation: word.translation,
                        transcription: word.transcription,
                        example: word.example,
                    })),
                );
            }

            if (item.questions.length) {
                await db.insert(textQuestions).values(
                    item.questions.map((question) => ({
                        textId,
                        orderIndex: question.orderIndex,
                        question: question.question,
                        answer: question.answer,
                    })),
                );
            }

            console.log(`Seeded: ${item.slug}`);
        }

        console.log('Seed completed successfully');
    } catch (error) {
        console.error('Seed failed:', error);
        process.exitCode = 1;
    } finally {
        await pool.end();
    }
}

void main();