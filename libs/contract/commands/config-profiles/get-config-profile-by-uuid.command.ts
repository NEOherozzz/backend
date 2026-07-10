import { z } from 'zod';

import { CONFIG_PROFILES_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { ConfigProfileSchema } from '../../models';

export namespace GetConfigProfileByUuidCommand {
    export const url = REST_API.CONFIG_PROFILES.GET_BY_UUID;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        CONFIG_PROFILES_ROUTES.GET_BY_UUID(':uuid'),
        'get',
        'Get config profile by uuid',
        { scope: 'get', kind: 'read' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: ConfigProfileSchema,
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
