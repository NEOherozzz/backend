import { RestartNodeCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class RestartNodeRequestDto extends createZodDto(RestartNodeCommand.RequestSchema) {}
export class RestartNodeRequestBodyDto extends createZodDto(RestartNodeCommand.RequestBodySchema) {}
export class RestartNodeResponseDto extends createZodDto(RestartNodeCommand.ResponseSchema) {}
