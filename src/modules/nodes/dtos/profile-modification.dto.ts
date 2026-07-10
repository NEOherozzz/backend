import { BulkNodesProfileModificationCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class ProfileModificationResponseDto extends createZodDto(
    BulkNodesProfileModificationCommand.ResponseSchema,
) {}

export class ProfileModificationRequestDto extends createZodDto(
    BulkNodesProfileModificationCommand.RequestSchema,
) {}
