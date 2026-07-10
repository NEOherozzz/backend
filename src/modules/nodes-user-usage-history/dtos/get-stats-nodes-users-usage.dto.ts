import { GetStatsNodesUsersUsageCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetStatsNodesUsersUsageRequestQueryDto extends createZodDto(
    GetStatsNodesUsersUsageCommand.RequestQuerySchema,
) {}

export class GetStatsNodesUsersUsageRequestDto extends createZodDto(
    GetStatsNodesUsersUsageCommand.RequestSchema,
) {}

export class GetStatsNodesUsersUsageResponseDto extends createZodDto(
    GetStatsNodesUsersUsageCommand.ResponseSchema,
) {}
