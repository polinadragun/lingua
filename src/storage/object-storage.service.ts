import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { randomUUID } from 'crypto';
import * as path from 'path';

const DEFAULT_ENDPOINT = 'https://storage.yandexcloud.net';
const DEFAULT_REGION = 'ru-central1';

const AUDIO_MIME_TO_EXT: Record<string, string> = {
    'audio/mpeg': '.mp3',
    'audio/mp3': '.mp3',
    'audio/wav': '.wav',
    'audio/x-wav': '.wav',
    'audio/ogg': '.ogg',
    'audio/webm': '.webm',
    'audio/mp4': '.m4a',
    'audio/x-m4a': '.m4a',
};

/** Bucket name only: no scheme, no path beyond the bucket segment. */
function normalizeBucketName(raw: string): string {
    const s = raw.trim();
    if (!s) return s;
    if (/^https?:\/\//i.test(s)) {
        try {
            const u = new URL(s);
            const host = u.hostname;
            const firstPath = u.pathname.replace(/^\//, '').split('/').filter(Boolean)[0] ?? '';
            if (host === 'storage.yandexcloud.net' && firstPath) {
                return firstPath;
            }
            if (host.endsWith('.storage.yandexcloud.net')) {
                return host.replace(/\.storage\.yandexcloud\.net$/i, '') || s;
            }
        } catch {
            /* fall through */
        }
    }
    return s.replace(/^\/+|\/+$/g, '');
}

function maskAccessKeyId(id: string): string {
    if (id.length <= 4) return '****';
    return `${id.slice(0, 4)}…`;
}

@Injectable()
export class ObjectStorageService {
    private readonly logger = new Logger(ObjectStorageService.name);

    private client: S3Client | null = null;
    private readonly bucket: string;
    private readonly publicBaseUrl: string;

    private resolvedEndpoint = DEFAULT_ENDPOINT;
    private resolvedRegion = DEFAULT_REGION;

    constructor(private readonly config: ConfigService) {
        const rawBucket =
            this.config.get<string>('YANDEX_STORAGE_BUCKET') ??
            this.config.get<string>('YC_S3_BUCKET') ??
            '';
        this.bucket = normalizeBucketName(rawBucket);

        const explicitPublic =
            this.config.get<string>('YANDEX_STORAGE_PUBLIC_BASE_URL')?.replace(/\/$/, '') ??
            this.config.get<string>('YC_S3_PUBLIC_BASE_URL')?.replace(/\/$/, '');
        this.publicBaseUrl =
            explicitPublic ?? `https://storage.yandexcloud.net/${this.bucket}`;
    }

    private getClient(): S3Client {
        if (this.client) {
            return this.client;
        }

        const accessKeyId =
            this.config.get<string>('YANDEX_STORAGE_ACCESS_KEY_ID')?.trim() ??
            this.config.get<string>('YC_S3_ACCESS_KEY_ID')?.trim();
        const secretAccessKey =
            this.config.get<string>('YANDEX_STORAGE_SECRET_ACCESS_KEY')?.trim() ??
            this.config.get<string>('YC_S3_SECRET_ACCESS_KEY')?.trim();

        this.resolvedRegion =
            (
                this.config.get<string>('YANDEX_STORAGE_REGION') ??
                this.config.get<string>('YC_S3_REGION') ??
                DEFAULT_REGION
            ).trim() || DEFAULT_REGION;

        this.resolvedEndpoint =
            (
                this.config.get<string>('YANDEX_STORAGE_ENDPOINT') ??
                this.config.get<string>('YC_S3_ENDPOINT') ??
                DEFAULT_ENDPOINT
            ).trim() || DEFAULT_ENDPOINT;

        this.logger.log(
            `Config (secrets omitted): YANDEX_STORAGE_BUCKET="${this.bucket || '(empty)'}" ` +
                `endpoint="${this.resolvedEndpoint}" region="${this.resolvedRegion}" ` +
                `accessKeyId=${accessKeyId ? maskAccessKeyId(accessKeyId) : '(missing)'}`,
        );

        if (!accessKeyId || !secretAccessKey || !this.bucket) {
            throw new ServiceUnavailableException(
                'Object storage is not configured. Set YANDEX_STORAGE_BUCKET, ' +
                    'YANDEX_STORAGE_ACCESS_KEY_ID, YANDEX_STORAGE_SECRET_ACCESS_KEY on the server.',
            );
        }

        this.client = new S3Client({
            region: this.resolvedRegion,
            endpoint: this.resolvedEndpoint,
            credentials: {
                accessKeyId,
                secretAccessKey,
            },
        });

        return this.client;
    }

    /**
     * Uploads audio bytes and returns a public HTTPS URL for the object.
     */
    async uploadPublicAudio(params: {
        textId: string;
        buffer: Buffer;
        originalName: string;
        mimeType: string;
    }): Promise<string> {
        const client = this.getClient();
        const ext = this.resolveExtension(params.mimeType, params.originalName);
        const key = `audio/${params.textId}/${randomUUID()}${ext}`;

        this.logger.log(
            `PutObject request: endpoint=${this.resolvedEndpoint} bucket="${this.bucket}" key="${key}"`,
        );

        await client.send(
            new PutObjectCommand({
                Bucket: this.bucket,
                Key: key,
                Body: params.buffer,
                ContentType: params.mimeType || 'application/octet-stream',
            }),
        );

        return `${this.publicBaseUrl}/${key}`;
    }

    private resolveExtension(mimeType: string, originalName: string): string {
        const fromMime = AUDIO_MIME_TO_EXT[mimeType.toLowerCase()];
        if (fromMime) return fromMime;
        const ext = path.extname(originalName).toLowerCase();
        if (ext && ext.length <= 8) return ext;
        return '.bin';
    }
}
