import { CreateNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class CreateNodeRequestDto extends createZodDto(CreateNodeCommand.RequestSchema) {}
export class CreateNodeResponseDto extends createZodDto(CreateNodeCommand.ResponseSchema) {}
