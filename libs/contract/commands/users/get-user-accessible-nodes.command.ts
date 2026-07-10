import { z } from 'zod';

import { REST_API, USERS_ROUTES } from '../../api';
import { getEndpointDetails } from '../../constants';

export namespace GetUserAccessibleNodesCommand {
    export const url = REST_API.USERS.ACCESSIBLE_NODES;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        USERS_ROUTES.ACCESSIBLE_NODES(':uuid'),
        'get',
        'Get user accessible nodes',
        { scope: 'accessible-nodes', kind: 'read' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            userUuid: z.string().uuid(),
            activeNodes: z.array(
                z.object({
                    uuid: z.string().uuid(),
                    nodeName: z.string(),
                    countryCode: z.string(),
                    configProfileUuid: z.string().uuid(),
                    configProfileName: z.string(),
                    activeSquads: z.array(
                        z.object({
                            squadName: z.string(),
                            activeInbounds: z.array(z.string()),
                        }),
                    ),
                }),
            ),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
