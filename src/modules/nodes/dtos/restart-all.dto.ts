import { RestartAllNodesCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class RestartAllNodesResponseDto extends createZodDto(
    RestartAllNodesCommand.ResponseSchema,
) {}

export class RestartAllNodesRequestBodyDto extends createZodDto(
    RestartAllNodesCommand.RequestBodySchema,
) {}
