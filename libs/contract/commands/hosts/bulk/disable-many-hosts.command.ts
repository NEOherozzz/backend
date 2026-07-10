import { z } from 'zod';

import { HOSTS_ROUTES, REST_API } from '../../../api';
import { getEndpointDetails } from '../../../constants';
import { HostsSchema } from '../../../models';

export namespace BulkDisableHostsCommand {
    export const url = REST_API.HOSTS.BULK.DISABLE_HOSTS;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        HOSTS_ROUTES.BULK.DISABLE_HOSTS,
        'post',
        'Disable hosts by UUIDs',
        { scope: 'bulk-disable', kind: 'write' },
    );

    export const RequestSchema = z.object({
        uuids: z.array(z.string().uuid()),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.array(HostsSchema),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
