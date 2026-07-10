import { GetStatsNodeUsersUsageCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetStatsNodeUsersUsageRequestQueryDto extends createZodDto(
    GetStatsNodeUsersUsageCommand.RequestQuerySchema,
) {}

export class GetStatsNodeUsersUsageRequestDto extends createZodDto(
    GetStatsNodeUsersUsageCommand.RequestSchema,
) {}

export class GetStatsNodeUsersUsageResponseDto extends createZodDto(
    GetStatsNodeUsersUsageCommand.ResponseSchema,
) {}
