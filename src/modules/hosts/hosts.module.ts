import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { HostsBulkActionsController, HostsController } from './controllers';
import { HostsConverter } from './hosts.converter';
import { HostsService } from './hosts.service';
import { QUERIES } from './queries';
import { HostsRepository } from './repositories/hosts.repository';

@Module({
    imports: [CqrsModule],
    controllers: [HostsController, HostsBulkActionsController],
    providers: [HostsRepository, HostsConverter, HostsService, ...QUERIES],
})
export class HostsModule {}
