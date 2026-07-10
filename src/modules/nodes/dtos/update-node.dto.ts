import { UpdateNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class UpdateNodeRequestDto extends createZodDto(UpdateNodeCommand.RequestSchema) {}
export class UpdateNodeResponseDto extends createZodDto(UpdateNodeCommand.ResponseSchema) {}
