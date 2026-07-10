import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { COMMANDS } from './commands';
import { HwidUserDevicesController } from './hwid-user-devices.controller';
import { HwidUserDevicesConverter } from './hwid-user-devices.converter';
import { HwidUserDevicesService } from './hwid-user-devices.service';
import { QUERIES } from './queries';
import { HwidUserDevicesRepository } from './repositories/hwid-user-devices.repository';

@Module({
    imports: [CqrsModule],
    controllers: [HwidUserDevicesController],
    providers: [
        HwidUserDevicesRepository,
        HwidUserDevicesConverter,
        HwidUserDevicesService,
        ...COMMANDS,
        ...QUERIES,
    ],
})
export class HwidUserDevicesModule {}
