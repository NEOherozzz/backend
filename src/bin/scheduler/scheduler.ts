(BigInt.prototype as any).toJSON = function () {
    return this.toString();
};

process.title = 'rw-scheduler';

import compression from 'compression';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import timezone from 'dayjs/plugin/timezone';
import utc from 'dayjs/plugin/utc';
import { json } from 'express';
import helmet from 'helmet';
import { utilities as nestWinstonModuleUtilities, WinstonModule } from 'nest-winston';
import { createLogger } from 'winston';
import * as winston from 'winston';

import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

import { TypedConfigService } from '@common/config/app-config';
import { NotFoundExceptionFilter } from '@common/exception/not-found-exception.filter';
import { WorkerRoutesGuard } from '@common/guards/worker-routes/worker-routes.guard';
import { customLogFilter } from '@common/utils/filter-logs/filter-logs';
import { getRedisConnectionOptions } from '@common/utils/get-redis-connection-options';
import { isDevOrDebugLogsEnabled } from '@common/utils/startup-app';
import { BULLBOARD_ROOT, HEALTH_ROOT, METRICS_ROOT } from '@libs/contracts/api';

import { SchedulerRootModule } from './scheduler.root.module';

dayjs.extend(utc);
dayjs.extend(relativeTime);
dayjs.extend(timezone);

// const levels = {
//     error: 0,
//     warn: 1,
//     info: 2,
//     http: 3,
//     verbose: 4,
//     debug: 5,
//     silly: 6,
// };

const instanedId = process.env.INSTANCE_ID || '0';

const logger = createLogger({
    transports: [new winston.transports.Console()],
    format: winston.format.combine(
        customLogFilter(),
        winston.format.timestamp({
            format: 'YYYY-MM-DD HH:mm:ss.SSS',
        }),
        // winston.format.ms(),
        winston.format.align(),
        nestWinstonModuleUtilities.format.nestLike(`Scheduler: #${instanedId}`, {
            colors: true,
            prettyPrint: true,
            processId: false,
            appName: true,
        }),
    ),
    level: isDevOrDebugLogsEnabled() ? 'debug' : 'http',
});

async function bootstrap(): Promise<void> {
    const app = await NestFactory.create(SchedulerRootModule, {
        logger: WinstonModule.createLogger({
            instance: logger,
        }),
    });

    app.use(json({ limit: '100mb' }));

    const config = app.get(TypedConfigService);

    app.use(
        helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'", '*'],
                    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", '*'],
                    imgSrc: ["'self'", 'data:', '*'],
                    connectSrc: ["'self'", '*'],
                    workerSrc: ["'self'", 'blob:', '*'],
                },
            },
        }),
    );

    app.use(compression());

    app.useGlobalFilters(new NotFoundExceptionFilter());

    app.useGlobalGuards(
        new WorkerRoutesGuard({ allowedPaths: [METRICS_ROOT, BULLBOARD_ROOT, HEALTH_ROOT] }),
    );

    app.connectMicroservice<MicroserviceOptions>({
        transport: Transport.REDIS,
        options: {
            ...getRedisConnectionOptions(
                config.get('REDIS_SOCKET'),
                config.get('REDIS_HOST'),
                config.get('REDIS_PORT'),
                'ioredis',
            ),
            db: config.getOrThrow('REDIS_DB'),
            password: config.get('REDIS_PASSWORD'),
            keyPrefix: 'nmicro:',
        },
    });

    await app.startAllMicroservices();

    app.enableShutdownHooks();

    await app.listen(config.getOrThrow('METRICS_PORT'));
}
void bootstrap();
