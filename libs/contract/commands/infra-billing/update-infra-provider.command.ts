import { z } from 'zod';

import { INFRA_BILLING_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { InfraProviderSchema } from '../../models';

export namespace UpdateInfraProviderCommand {
    export const url = REST_API.INFRA_BILLING.UPDATE_PROVIDER;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        INFRA_BILLING_ROUTES.UPDATE_PROVIDER,
        'patch',
        'Update infra provider',
        { scope: 'update-provider', kind: 'write' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
        name: z
            .string()
            .min(2, 'Name must be at least 2 characters')
            .max(30, 'Name must be less than 30 characters')
            .optional(),
        faviconLink: z.optional(z.nullable(z.string().url())),
        loginUrl: z.optional(z.nullable(z.string().url())),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: InfraProviderSchema,
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
