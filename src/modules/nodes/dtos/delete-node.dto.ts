import { DeleteNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class DeleteNodeRequestParamDto extends createZodDto(DeleteNodeCommand.RequestSchema) {}
export class DeleteNodeResponseDto extends createZodDto(DeleteNodeCommand.ResponseSchema) {}
