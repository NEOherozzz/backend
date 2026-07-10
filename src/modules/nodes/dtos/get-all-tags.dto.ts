import { GetAllNodesTagsCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetAllNodesTagsResponseDto extends createZodDto(
    GetAllNodesTagsCommand.ResponseSchema,
) {}
