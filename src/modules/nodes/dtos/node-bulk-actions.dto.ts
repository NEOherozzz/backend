import { BulkNodesActionsCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class BulkNodesActionsResponseDto extends createZodDto(
    BulkNodesActionsCommand.ResponseSchema,
) {}

export class BulkNodesActionsRequestDto extends createZodDto(
    BulkNodesActionsCommand.RequestSchema,
) {}
