import { z } from 'zod';

import { REST_API, USERS_ROUTES } from '../../../api';
import { getEndpointDetails } from '../../../constants';
import { ExtendedUsersSchema } from '../../../models';

export namespace GetUserByUsernameCommand {
    export const url = REST_API.USERS.GET_BY.USERNAME;
    export const TSQ_url = url(':username');

    export const endpointDetails = getEndpointDetails(
        USERS_ROUTES.GET_BY.USERNAME(':username'),
        'get',
        'Get user by username',
        { scope: 'by-username', kind: 'read' },
    );

    export const RequestSchema = z.object({
        username: z.string(),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: ExtendedUsersSchema,
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
