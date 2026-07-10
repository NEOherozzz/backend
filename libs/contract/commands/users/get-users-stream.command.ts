import { z } from 'zod';

import { REST_API, USERS_ROUTES } from '../../api';
import { getEndpointDetails } from '../../constants';
import { ExtendedUsersSchema } from '../../models';

export namespace GetUsersStreamCommand {
    export const url = REST_API.USERS.STREAM;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        USERS_ROUTES.STREAM,
        'get',
        'Get all users using cursor-based (keyset) pagination',
        { scope: 'stream', kind: 'read' },
    );

    export const RequestQuerySchema = z.object({
        cursor: z
            .string()
            .regex(/^\d+$/, 'Cursor must be a positive integer string')
            .optional()
            .describe(
                'Cursor for pagination — pass the nextCursor from the previous response. Omit on the first request.',
            ),
        size: z.coerce
            .number()
            .int()
            .min(1, 'Size (limit) must be greater than 0')
            .max(1000, 'Size (limit) must be less than 1000')
            .describe('Number of results to return, no more than 1000')
            .default(250),
    });

    export type RequestQuery = z.infer<typeof RequestQuerySchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            users: z.array(ExtendedUsersSchema),
            nextCursor: z
                .string()
                .nullable()
                .describe('Cursor to fetch the next page, or null if there are no more results'),
            hasMore: z.boolean().describe('Whether there are more results to fetch'),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
