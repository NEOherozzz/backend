import { DisableNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class DisableNodeRequestParamDto extends createZodDto(DisableNodeCommand.RequestSchema) {}
export class DisableNodeResponseDto extends createZodDto(DisableNodeCommand.ResponseSchema) {}
