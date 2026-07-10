import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { COMMANDS } from './commands';
import { NodesTrafficUsageHistoryConverter } from './nodes-traffic-usage-history.converter';
import { NodesTrafficUsageHistoryRepository } from './repositories/nodes-traffic-usage-history.repository';

@Module({
    imports: [CqrsModule],
    controllers: [],
    providers: [NodesTrafficUsageHistoryRepository, NodesTrafficUsageHistoryConverter, ...COMMANDS],
})
export class NodesTrafficUsageHistoryModule {}
