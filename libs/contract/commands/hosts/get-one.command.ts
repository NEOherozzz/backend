import { z } from 'zod';

import { HOSTS_ROUTES, REST_API } from '../../api';
import { getEndpointDetails } from '../../constants';
import { HostsSchema } from '../../models';

export namespace GetOneHostCommand {
    export const url = REST_API.HOSTS.GET_BY_UUID;
    export const TSQ_url = url(':uuid');

    export const endpointDetails = getEndpointDetails(
        HOSTS_ROUTES.GET_BY_UUID(':uuid'),
        'get',
        'Get a host by UUID',
        { scope: 'get', kind: 'read' },
    );

    export const RequestSchema = z.object({
        uuid: z.string().uuid(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: HostsSchema,
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
