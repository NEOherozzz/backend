import { BulkNodesUpdateCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class BulkNodesUpdateResponseDto extends createZodDto(
    BulkNodesUpdateCommand.ResponseSchema,
) {}

export class BulkNodesUpdateRequestDto extends createZodDto(BulkNodesUpdateCommand.RequestSchema) {}
