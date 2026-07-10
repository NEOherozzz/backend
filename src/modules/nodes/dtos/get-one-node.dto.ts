import { GetOneNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetOneNodeRequestParamDto extends createZodDto(GetOneNodeCommand.RequestSchema) {}
export class GetOneNodeResponseDto extends createZodDto(GetOneNodeCommand.ResponseSchema) {}
