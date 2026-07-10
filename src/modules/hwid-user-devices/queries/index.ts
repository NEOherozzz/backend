import { CheckHwidExistsHandler } from './check-hwid-exists/check-hwid-exists.handler';
import { CountUsersDevicesHandler } from './count-users-devices/count-users-devices.handler';

export const QUERIES = [CountUsersDevicesHandler, CheckHwidExistsHandler];
