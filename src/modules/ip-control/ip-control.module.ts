import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { IpControlController } from './ip-control.controller';
import { IpControlService } from './ip-control.service';

@Module({
    imports: [CqrsModule],
    controllers: [IpControlController],
    providers: [IpControlService],
})
export class IpControlModule {}
