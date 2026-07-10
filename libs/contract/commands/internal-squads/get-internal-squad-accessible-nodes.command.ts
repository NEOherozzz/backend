import { z } from 'zod';

import { INTERNAL_SQUADS_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';

export namespace GetInternalSquadAccessibleNodesCommand {
    export const url = REST_API.INTERNAL_SQUADS.ACCESSIBLE_NODES;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        INTERNAL_SQUADS_ROUTES.ACCESSIBLE_NODES(':uuid'),
        'get',
        'Get internal squad accessible nodes',
        { scope: 'accessible-nodes', kind: 'read' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            squadUuid: z.string().uuid(),
            accessibleNodes: z.array(
                z.object({
                    uuid: z.string().uuid(),
                    nodeName: z.string(),
                    countryCode: z.string(),
                    configProfileUuid: z.string().uuid(),
                    configProfileName: z.string(),
                    activeInbounds: z.array(z.string()),
                }),
            ),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
