import { z } from 'zod';

import { CONFIG_PROFILES_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { ConfigProfileInboundsSchema } from '../../models';

export namespace GetInboundsByProfileUuidCommand {
    export const url = REST_API.CONFIG_PROFILES.GET_INBOUNDS_BY_PROFILE_UUID;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        CONFIG_PROFILES_ROUTES.GET_INBOUNDS_BY_PROFILE_UUID(':uuid'),
        'get',
        'Get inbounds by profile uuid',
        { scope: 'list-profile-inbounds', kind: 'read' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            total: z.number(),
            inbounds: z.array(
                ConfigProfileInboundsSchema.extend({
                    activeSquads: z.array(z.string().uuid()),
                }),
            ),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
