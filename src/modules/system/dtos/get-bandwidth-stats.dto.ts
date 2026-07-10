import { GetBandwidthStatsCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetBandwidthStatsRequestQueryDto extends createZodDto(
    GetBandwidthStatsCommand.RequestQuerySchema,
) {}
export class GetBandwidthStatsResponseDto extends createZodDto(
    GetBandwidthStatsCommand.ResponseSchema,
) {}
