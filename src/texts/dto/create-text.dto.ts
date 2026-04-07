import { Type } from 'class-transformer';
import {
    IsArray,
    IsEmail,
    IsNotEmpty,
    IsNumber,
    IsOptional,
    IsString,
    Min,
    ValidateNested,
} from 'class-validator';

export class CreateSentenceDto {
    @IsNumber()
    @Min(1)
    orderIndex!: number;

    @IsString()
    @IsNotEmpty()
    text!: string;

    @IsNumber()
    start!: number;

    @IsNumber()
    end!: number;
}

export class CreateWordDto {
    @IsString()
    @IsNotEmpty()
    key!: string;

    @IsString()
    @IsNotEmpty()
    word!: string;

    @IsString()
    @IsNotEmpty()
    translation!: string;

    @IsString()
    @IsNotEmpty()
    transcription!: string;

    @IsString()
    @IsNotEmpty()
    example!: string;
}

export class CreateQuestionDto {
    @IsNumber()
    @Min(1)
    orderIndex!: number;

    @IsString()
    @IsNotEmpty()
    question!: string;

    @IsString()
    @IsNotEmpty()
    answer!: string;
}

export class CreateTextDto {
    @IsString()
    @IsNotEmpty()
    title!: string;

    @IsOptional()
    @IsString()
    description?: string;

    @IsString()
    @IsNotEmpty()
    level!: string;

    @IsString()
    @IsNotEmpty()
    topic!: string;

    @IsOptional()
    @IsString()
    length?: string;

    @IsOptional()
    @IsString()
    language?: string;

    /** Ignored when request is authenticated; server sets author from JWT. */
    @IsOptional()
    @IsEmail()
    authorEmail?: string;

    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => CreateSentenceDto)
    sentences!: CreateSentenceDto[];

    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => CreateWordDto)
    words!: CreateWordDto[];

    @IsOptional()
    @IsArray()
    @ValidateNested({ each: true })
    @Type(() => CreateQuestionDto)
    questions?: CreateQuestionDto[];
}
