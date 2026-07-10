import { GetStatsCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetStatsRequestQueryDto extends createZodDto(GetStatsCommand.RequestQuerySchema) {}
export class GetStatsResponseDto extends createZodDto(GetStatsCommand.ResponseSchema) {}
