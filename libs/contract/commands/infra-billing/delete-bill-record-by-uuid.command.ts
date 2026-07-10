import { z } from 'zod';

import { INFRA_BILLING_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { InfraBillingHistoryRecordSchema } from '../../models';

export namespace DeleteInfraBillingHistoryRecordCommand {
    export const url = REST_API.INFRA_BILLING.DELETE_BILLING_HISTORY;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        INFRA_BILLING_ROUTES.DELETE_BILLING_HISTORY(':uuid'),
        'delete',
        'Delete infra billing history',
        { scope: 'delete-bill-record', kind: 'write' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
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
