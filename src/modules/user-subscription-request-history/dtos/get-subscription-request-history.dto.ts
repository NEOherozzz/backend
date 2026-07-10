import { GetSubscriptionRequestHistoryCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetSubscriptionRequestHistoryRequestQueryDto extends createZodDto(
    GetSubscriptionRequestHistoryCommand.RequestQuerySchema,
) {}

export class GetSubscriptionRequestHistoryResponseDto extends createZodDto(
    GetSubscriptionRequestHistoryCommand.ResponseSchema,
) {}
