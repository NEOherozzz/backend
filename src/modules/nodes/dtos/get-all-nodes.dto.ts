import { GetAllNodesCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetAllNodesResponseDto extends createZodDto(GetAllNodesCommand.ResponseSchema) {}
