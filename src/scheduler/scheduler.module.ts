import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { PrometheusReporterModule } from '@integration-modules/prometheus-reporter/prometheus-reporter.module';

import { ENQUEUE_SERVICES } from './enqueue';
import { EVENT_LISTENERS } from './events';
import { METRIC_PROVIDERS } from './metrics-providers';
import { JOBS_SERVICES } from './tasks';
import { NodesMetricMessageController } from './tasks/export-metrics/nodes-metric-message.controller';

@Module({
    imports: [CqrsModule, PrometheusReporterModule],
    controllers: [NodesMetricMessageController],
    providers: [...ENQUEUE_SERVICES, ...JOBS_SERVICES, ...METRIC_PROVIDERS, ...EVENT_LISTENERS],
})
export class SchedulerModule {}
