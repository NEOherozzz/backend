import { Injectable, Logger } from '@nestjs/common';
import { QueryBus } from '@nestjs/cqrs';

import { fail, ok, TResult } from '@common/types';
import { nullifyEmpty } from '@common/utils/convert-type';
import { ERRORS } from '@libs/contracts/constants';

import { GetConfigProfileByUuidQuery } from '@modules/config-profiles/queries/get-config-profile-by-uuid';
import { ReorderHostRequestDto } from '@modules/hosts/dtos/reorder-hosts.dto';
import { GetSubscriptionTemplateByUuidQuery } from '@modules/subscription-template/queries/get-template-by-uuid';

import { UpdateHostRequestDto, UpdateManyHostsRequestDto } from './dtos';
import { CreateHostRequestDto } from './dtos/create-host.dto';
import { HostsEntity } from './entities/hosts.entity';
import { DeleteHostResponseModel } from './models/delete-host.response.model';
import { HostsRepository } from './repositories/hosts.repository';

@Injectable()
export class HostsService {
    private readonly logger = new Logger(HostsService.name);
    constructor(
        private readonly hostsRepository: HostsRepository,
        private readonly queryBus: QueryBus,
    ) {}

    public async createHost(dto: CreateHostRequestDto): Promise<TResult<HostsEntity>> {
        try {
            if (dto.xrayJsonTemplateUuid) {
                const xrayJsonTemplate = await this.queryBus.execute(
                    new GetSubscriptionTemplateByUuidQuery(dto.xrayJsonTemplateUuid),
                );

                if (!xrayJsonTemplate.isOk) {
                    return fail(ERRORS.SUBSCRIPTION_TEMPLATE_NOT_FOUND);
                }

                if (xrayJsonTemplate.response.templateType !== 'XRAY_JSON') {
                    return fail(ERRORS.TEMPLATE_TYPE_NOT_ALLOWED);
                }
            }

            const {
                inbound: inboundObj,
                nodes,
                excludedInternalSquads,
                xhttpExtraParams,
                muxParams,
                sockoptParams,
                finalMask,
                ...rest
            } = dto;

            const configProfile = await this.queryBus.execute(
                new GetConfigProfileByUuidQuery(inboundObj.configProfileUuid),
            );

            if (!configProfile.isOk) {
                return fail(ERRORS.CONFIG_PROFILE_NOT_FOUND);
            }

            const configProfileInbound = configProfile.response.inbounds.find(
                (inbound) => inbound.uuid === inboundObj.configProfileInboundUuid,
            );
            if (!configProfileInbound) {
                return fail(ERRORS.CONFIG_PROFILE_INBOUND_NOT_FOUND_IN_SPECIFIED_PROFILE);
            }

            const hostEntity = new HostsEntity({
                ...rest,
                address: dto.address.trim(),
                xhttpExtraParams: nullifyEmpty(xhttpExtraParams),
                muxParams: nullifyEmpty(muxParams),
                sockoptParams: nullifyEmpty(sockoptParams),
                finalMask: nullifyEmpty(finalMask),
                configProfileUuid: configProfile.response.uuid,
                configProfileInboundUuid: configProfileInbound.uuid,
            });

            const result = await this.hostsRepository.create(hostEntity);

            if (nodes !== undefined && nodes.length > 0) {
                await this.hostsRepository.addNodesToHost(result.uuid, nodes);
                result.nodes = nodes.map((node) => {
                    return {
                        nodeUuid: node,
                    };
                });
            }

            if (excludedInternalSquads !== undefined && excludedInternalSquads.length > 0) {
                await this.hostsRepository.addExcludedInternalSquadsToHost(
                    result.uuid,
                    excludedInternalSquads,
                );
                result.excludedInternalSquads = excludedInternalSquads.map((squad) => {
                    return {
                        squadUuid: squad,
                    };
                });
            }

            return ok(result);
        } catch (error) {
            this.logger.error(error);

            return fail(ERRORS.CREATE_HOST_ERROR);
        }
    }

    public async updateHost(dto: UpdateHostRequestDto): Promise<TResult<HostsEntity>> {
        try {
            const { inbound: inboundObj, nodes, excludedInternalSquads, ...rest } = dto;

            const host = await this.hostsRepository.findByUUID(dto.uuid);
            if (!host) return fail(ERRORS.HOST_NOT_FOUND);

            if (dto.xrayJsonTemplateUuid) {
                const xrayJsonTemplate = await this.queryBus.execute(
                    new GetSubscriptionTemplateByUuidQuery(dto.xrayJsonTemplateUuid),
                );

                if (!xrayJsonTemplate.isOk) {
                    return fail(ERRORS.SUBSCRIPTION_TEMPLATE_NOT_FOUND);
                }

                if (xrayJsonTemplate.response.templateType !== 'XRAY_JSON') {
                    return fail(ERRORS.TEMPLATE_TYPE_NOT_ALLOWED);
                }
            }

            let xhttpExtraParams: null | object | undefined;
            if (dto.xhttpExtraParams !== undefined && dto.xhttpExtraParams !== null) {
                xhttpExtraParams = dto.xhttpExtraParams;
            } else if (dto.xhttpExtraParams === null) {
                xhttpExtraParams = null;
            } else {
                xhttpExtraParams = undefined;
            }

            let muxParams: null | object | undefined;
            if (dto.muxParams !== undefined && dto.muxParams !== null) {
                if (Object.keys(dto.muxParams).length === 0) {
                    muxParams = null;
                } else {
                    muxParams = dto.muxParams;
                }
            } else if (dto.muxParams === null) {
                muxParams = null;
            } else {
                muxParams = undefined;
            }

            let sockoptParams: null | object | undefined;
            if (dto.sockoptParams !== undefined && dto.sockoptParams !== null) {
                if (Object.keys(dto.sockoptParams).length === 0) {
                    sockoptParams = null;
                } else {
                    sockoptParams = dto.sockoptParams;
                }
            } else if (dto.sockoptParams === null) {
                sockoptParams = null;
            } else {
                sockoptParams = undefined;
            }

            let serverDescription: null | string | undefined;
            if (dto.serverDescription !== undefined && dto.serverDescription !== null) {
                serverDescription = dto.serverDescription;
            } else if (dto.serverDescription === null) {
                serverDescription = null;
            } else {
                serverDescription = undefined;
            }

            let finalMask: null | object | undefined;
            if (dto.finalMask !== undefined && dto.finalMask !== null) {
                finalMask = dto.finalMask;
            } else if (dto.finalMask === null) {
                finalMask = null;
            } else {
                finalMask = undefined;
            }

            let configProfileUuid: string | undefined;
            let configProfileInboundUuid: string | undefined;
            if (inboundObj) {
                const configProfile = await this.queryBus.execute(
                    new GetConfigProfileByUuidQuery(inboundObj.configProfileUuid),
                );

                if (!configProfile.isOk) {
                    return fail(ERRORS.CONFIG_PROFILE_NOT_FOUND);
                }

                const configProfileInbound = configProfile.response.inbounds.find(
                    (inbound) => inbound.uuid === inboundObj.configProfileInboundUuid,
                );

                if (!configProfileInbound) {
                    return fail(ERRORS.CONFIG_PROFILE_INBOUND_NOT_FOUND_IN_SPECIFIED_PROFILE);
                }

                configProfileUuid = configProfile.response.uuid;
                configProfileInboundUuid = configProfileInbound.uuid;
            }

            if (nodes !== undefined) {
                await this.hostsRepository.clearNodesFromHost(host.uuid);
                await this.hostsRepository.addNodesToHost(host.uuid, nodes);
            }

            if (excludedInternalSquads !== undefined) {
                await this.hostsRepository.clearExcludedInternalSquadsFromHost(host.uuid);
                await this.hostsRepository.addExcludedInternalSquadsToHost(
                    host.uuid,
                    excludedInternalSquads,
                );
            }

            const result = await this.hostsRepository.update({
                ...rest,
                address: dto.address ? dto.address.trim() : undefined,
                xhttpExtraParams,
                muxParams,
                sockoptParams,
                configProfileUuid,
                configProfileInboundUuid,
                serverDescription,
                finalMask,
            });

            return ok(result);
        } catch (error) {
            this.logger.error(error);

            return fail(ERRORS.UPDATE_HOST_ERROR);
        }
    }

    public async deleteHost(hostUuid: string): Promise<TResult<DeleteHostResponseModel>> {
        try {
            const host = await this.hostsRepository.findByUUID(hostUuid);
            if (!host) {
                return fail(ERRORS.HOST_NOT_FOUND);
            }
            const result = await this.hostsRepository.deleteByUUID(host.uuid);

            return ok(new DeleteHostResponseModel({ isDeleted: result }));
        } catch (error) {
            this.logger.error(error);
            this.logger.error(JSON.stringify(error));
            return fail(ERRORS.DELETE_HOST_ERROR);
        }
    }

    public async getAllHosts(): Promise<TResult<HostsEntity[]>> {
        try {
            const result = await this.hostsRepository.findAll();

            return ok(result);
        } catch (error) {
            this.logger.error(JSON.stringify(error));
            return fail(ERRORS.GET_ALL_HOSTS_ERROR);
        }
    }

    public async getOneHost(hostUuid: string): Promise<TResult<HostsEntity>> {
        try {
            const result = await this.hostsRepository.findByUUID(hostUuid);

            if (!result) {
                return fail(ERRORS.HOST_NOT_FOUND);
            }

            return ok(result);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.GET_ONE_HOST_ERROR);
        }
    }

    public async reorderHosts(dto: ReorderHostRequestDto): Promise<
        TResult<{
            isUpdated: boolean;
        }>
    > {
        try {
            const result = await this.hostsRepository.reorderMany(dto.hosts);

            return ok({ isUpdated: result });
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.REORDER_HOSTS_ERROR);
        }
    }

    public async deleteHosts(uuids: string[]): Promise<TResult<HostsEntity[]>> {
        try {
            await this.hostsRepository.deleteMany(uuids);

            const result = await this.getAllHosts();

            if (!result.isOk) {
                return fail(ERRORS.DELETE_HOSTS_ERROR);
            }

            return ok(result.response);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.DELETE_HOSTS_ERROR);
        }
    }

    public async bulkEnableHosts(uuids: string[]): Promise<TResult<HostsEntity[]>> {
        try {
            await this.hostsRepository.enableMany(uuids);

            const result = await this.getAllHosts();

            if (!result.isOk) {
                return fail(ERRORS.BULK_ENABLE_HOSTS_ERROR);
            }

            return ok(result.response);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.BULK_ENABLE_HOSTS_ERROR);
        }
    }

    public async bulkDisableHosts(uuids: string[]): Promise<TResult<HostsEntity[]>> {
        try {
            await this.hostsRepository.disableMany(uuids);

            const result = await this.getAllHosts();

            if (!result.isOk) {
                return fail(ERRORS.BULK_DISABLE_HOSTS_ERROR);
            }

            return ok(result.response);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.BULK_DISABLE_HOSTS_ERROR);
        }
    }

    public async getAllHostTags(): Promise<TResult<string[]>> {
        try {
            const result = await this.hostsRepository.findAllTags();

            return ok(result);
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.GET_ALL_HOST_TAGS_ERROR);
        }
    }

    public async updateManyHosts(dto: UpdateManyHostsRequestDto): Promise<TResult<HostsEntity[]>> {
        try {
            const {
                uuids,
                inbound: inboundObj,
                nodes,
                excludedInternalSquads,
                xhttpExtraParams,
                muxParams,
                sockoptParams,
                finalMask,
                ...rest
            } = dto;

            if (dto.xrayJsonTemplateUuid) {
                const xrayJsonTemplate = await this.queryBus.execute(
                    new GetSubscriptionTemplateByUuidQuery(dto.xrayJsonTemplateUuid),
                );

                if (!xrayJsonTemplate.isOk) {
                    return fail(ERRORS.SUBSCRIPTION_TEMPLATE_NOT_FOUND);
                }

                if (xrayJsonTemplate.response.templateType !== 'XRAY_JSON') {
                    return fail(ERRORS.TEMPLATE_TYPE_NOT_ALLOWED);
                }
            }

            let configProfileUuid: string | undefined;
            let configProfileInboundUuid: string | undefined;
            if (inboundObj) {
                const configProfile = await this.queryBus.execute(
                    new GetConfigProfileByUuidQuery(inboundObj.configProfileUuid),
                );

                if (!configProfile.isOk) {
                    return fail(ERRORS.CONFIG_PROFILE_NOT_FOUND);
                }

                const configProfileInbound = configProfile.response.inbounds.find(
                    (inbound) => inbound.uuid === inboundObj.configProfileInboundUuid,
                );

                if (!configProfileInbound) {
                    return fail(ERRORS.CONFIG_PROFILE_INBOUND_NOT_FOUND_IN_SPECIFIED_PROFILE);
                }

                configProfileUuid = configProfile.response.uuid;
                configProfileInboundUuid = configProfileInbound.uuid;
            }

            if (nodes !== undefined) {
                await this.hostsRepository.clearNodesFromHosts(uuids);
                await this.hostsRepository.addNodesToHosts(uuids, nodes);
            }

            if (excludedInternalSquads !== undefined) {
                await this.hostsRepository.clearExcludedInternalSquadsFromHosts(uuids);
                await this.hostsRepository.addExcludedInternalSquadsToHosts(
                    uuids,
                    excludedInternalSquads,
                );
            }

            await this.hostsRepository.updateMany({
                uuids,
                data: {
                    ...rest,
                    address: dto.address ? dto.address.trim() : undefined,
                    xhttpExtraParams: nullifyEmpty(xhttpExtraParams),
                    muxParams: nullifyEmpty(muxParams),
                    sockoptParams: nullifyEmpty(sockoptParams),
                    finalMask: nullifyEmpty(finalMask),
                    configProfileUuid,
                    configProfileInboundUuid,
                },
            });

            return await this.getAllHosts();
        } catch (error) {
            this.logger.error(error);
            return fail(ERRORS.UPDATE_HOSTS_ERROR);
        }
    }
}
