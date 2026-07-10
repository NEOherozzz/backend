import { GetStatsUserUsageCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetStatsUserUsageRequestQueryDto extends createZodDto(
    GetStatsUserUsageCommand.RequestQuerySchema,
) {}

export class GetStatsUserUsageRequestDto extends createZodDto(
    GetStatsUserUsageCommand.RequestSchema,
) {}

export class GetStatsUserUsageResponseDto extends createZodDto(
    GetStatsUserUsageCommand.ResponseSchema,
) {}
