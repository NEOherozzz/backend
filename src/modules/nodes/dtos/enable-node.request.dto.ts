import { EnableNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class EnableNodeRequestParamDto extends createZodDto(EnableNodeCommand.RequestSchema) {}
export class EnableNodeResponseDto extends createZodDto(EnableNodeCommand.ResponseSchema) {}
