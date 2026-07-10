import { z } from 'zod';

import { REST_API, NODE_PLUGINS_ROUTES } from '../../../api';
import { getEndpointDetails } from '../../../constants';
import { TorrentBlockerReportSchema } from '../../../models';

export namespace TruncateTorrentBlockerReportsCommand {
    export const url = REST_API.NODE_PLUGINS.TORRENT_BLOCKER.TRUNCATE_REPORTS;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        NODE_PLUGINS_ROUTES.TORRENT_BLOCKER.TRUNCATE_REPORTS,
        'delete',
        'Truncate Torrent Blocker Reports',
        { scope: 'truncate', kind: 'write' },
    );

    export const ResponseSchema = z.object({
        response: z.object({
            records: z.array(TorrentBlockerReportSchema),
            total: z.number(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
