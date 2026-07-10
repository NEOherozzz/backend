import { GetNodesStatisticsCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetNodesStatisticsRequestQueryDto extends createZodDto(
    GetNodesStatisticsCommand.RequestQuerySchema,
) {}
export class GetNodesStatisticsResponseDto extends createZodDto(
    GetNodesStatisticsCommand.ResponseSchema,
) {}
