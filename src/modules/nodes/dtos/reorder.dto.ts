import { ReorderNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class ReorderNodeRequestDto extends createZodDto(ReorderNodeCommand.RequestSchema) {}
export class ReorderNodeResponseDto extends createZodDto(ReorderNodeCommand.ResponseSchema) {}
