import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';

import { PrometheusReporterModule } from '@integration-modules/prometheus-reporter/prometheus-reporter.module';

import { ENQUEUE_SERVICES } from './enqueue';
import { EVENT_LISTENERS } from './events';
import { METRIC_PROVIDERS } from './metrics-providers';
import { JOBS_SERVICES } from './tasks';
import { NodeMetricsSubscriber } from './tasks/export-metrics/node-metrics.subscriber';

@Module({
    imports: [CqrsModule, PrometheusReporterModule],
    controllers: [],
    providers: [
        ...ENQUEUE_SERVICES,
        ...JOBS_SERVICES,
        ...METRIC_PROVIDERS,
        ...EVENT_LISTENERS,
        NodeMetricsSubscriber,
    ],
})
export class SchedulerModule {}
