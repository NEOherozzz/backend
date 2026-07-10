import { z } from 'zod';

import { INFRA_BILLING_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { InfraBillingHistoryRecordSchema } from '../../models';

export namespace CreateInfraBillingHistoryRecordCommand {
    export const url = REST_API.INFRA_BILLING.CREATE_BILLING_HISTORY;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        INFRA_BILLING_ROUTES.CREATE_BILLING_HISTORY,
        'post',
        'Create infra billing history',
        { scope: 'create-bill-record', kind: 'write' },
    );

    export const RequestSchema = z.object({
        providerUuid: z.string().uuid(),
        amount: z.number().min(0, 'Amount must be greater than 0'),
        billedAt: z
            .string({
                invalid_type_error: 'Invalid date format',
            })
            .datetime({ message: 'Invalid date format', offset: true, local: true })
            .transform((str) => new Date(str))
            .describe('Billing date. Format: 2025-01-17T15:38:45.065Z'),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            records: z.array(InfraBillingHistoryRecordSchema),
            total: z.number(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
