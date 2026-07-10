import { GetStatsNodesUsageCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetStatsNodesUsageRequestQueryDto extends createZodDto(
    GetStatsNodesUsageCommand.RequestQuerySchema,
) {}
export class GetStatsNodesUsageResponseDto extends createZodDto(
    GetStatsNodesUsageCommand.ResponseSchema,
) {}
