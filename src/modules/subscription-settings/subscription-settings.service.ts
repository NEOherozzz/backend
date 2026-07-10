import { Injectable, Logger } from '@nestjs/common';

import { RawCacheService } from '@common/raw-cache';
import { fail, ok, TResult } from '@common/types';
import { CACHE_KEYS, ERRORS } from '@libs/contracts/constants';

import { ResponseRulesParserService } from '@modules/subscription-response-rules/services/response-rules-parser.service';

import { UpdateSubscriptionSettingsRequestDto } from './dtos';
import { SubscriptionSettingsEntity } from './entities/subscription-settings.entity';
import { SubscriptionSettingsRepository } from './repositories/subscription-settings.repository';

@Injectable()
export class SubscriptionSettingsService {
    private readonly logger = new Logger(SubscriptionSettingsService.name);

    constructor(
        private readonly rawCacheService: RawCacheService,
        private readonly srrParser: ResponseRulesParserService,
        private readonly subscriptionSettingsRepository: SubscriptionSettingsRepository,
    ) {}

    public async getSubscriptionSettings(): Promise<TResult<SubscriptionSettingsEntity>> {
        try {
            const settings = await this.subscriptionSettingsRepository.findFirst();

            if (!settings) {
                return fail(ERRORS.SUBSCRIPTION_SETTINGS_NOT_FOUND);
            }

            return ok(settings);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.GET_SUBSCRIPTION_SETTINGS_ERROR);
        }
    }

    public async updateSettings(
        dto: UpdateSubscriptionSettingsRequestDto,
    ): Promise<TResult<SubscriptionSettingsEntity>> {
        try {
            const settings = await this.subscriptionSettingsRepository.findByUUID(dto.uuid);

            if (!settings) {
                return fail(ERRORS.SUBSCRIPTION_SETTINGS_NOT_FOUND);
            }

            if (dto.responseRules) {
                try {
                    dto.responseRules = await this.srrParser.parseConfig(dto.responseRules);
                } catch (error) {
                    return fail(
                        ERRORS.CONFIG_VALIDATION_ERROR.withMessage(
                            error instanceof Error ? error.message : 'Unknown error',
                        ),
                    );
                }
            }

            const updatedSettings = await this.subscriptionSettingsRepository.update({
                ...dto,
            });

            await this.rawCacheService.del(CACHE_KEYS.SUBSCRIPTION_SETTINGS);

            return ok(updatedSettings);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.UPDATE_SUBSCRIPTION_SETTINGS_ERROR);
        }
    }
}
