import { GetNotConnectedUsersHandler } from './get-not-connected-users';
import { GetPreparedConfigWithUsersHandler } from './get-prepared-config-with-users';
import { GetShortUserStatsHandler } from './get-short-user-stats';
import { GetUserByUniqueFieldHandler } from './get-user-by-unique-field';
import { GetUserIdByUuidHandler } from './get-user-id-by-uuid';
import { GetUserIdsByUserUuidsHandler } from './get-user-ids-by-user-uuids';
import { GetUserSubpageConfigHandler } from './get-user-subpage-config';
import { GetUserWithResolvedInboundsHandler } from './get-user-with-resolved-inbounds';
import { GetUsersByExpireAtHandler } from './get-users-by-expire-at';
import { GetUsersRecapHandler } from './get-users-recap';
import { GetUsersWithPaginationHandler } from './get-users-with-pagination';
import { GetUsersWithResolvedInboundsHandler } from './get-users-with-resolved-inbounds';

export const QUERIES = [
    GetUserByUniqueFieldHandler,
    GetUserWithResolvedInboundsHandler,
    GetShortUserStatsHandler,
    GetPreparedConfigWithUsersHandler,
    GetUsersByExpireAtHandler,
    GetUsersWithPaginationHandler,
    GetNotConnectedUsersHandler,
    GetUserSubpageConfigHandler,
    GetUsersWithResolvedInboundsHandler,
    GetUserIdsByUserUuidsHandler,
    GetUserIdByUuidHandler,
    GetUsersRecapHandler,
];
