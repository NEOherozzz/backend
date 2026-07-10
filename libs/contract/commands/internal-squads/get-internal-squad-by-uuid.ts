import { z } from 'zod';

import { INTERNAL_SQUADS_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { InternalSquadSchema } from '../../models';

export namespace GetInternalSquadByUuidCommand {
    export const url = REST_API.INTERNAL_SQUADS.GET_BY_UUID;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        INTERNAL_SQUADS_ROUTES.GET_BY_UUID(':uuid'),
        'get',
        'Get internal squad by uuid',
        { scope: 'get', kind: 'read' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: InternalSquadSchema,
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
