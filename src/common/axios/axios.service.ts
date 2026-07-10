import { ERRORS } from '@contract/constants';
import { compress } from '@mongodb-js/zstd';
import axios, { AxiosError, AxiosInstance } from 'axios';
import https from 'node:https';

import { Injectable, Logger } from '@nestjs/common';
import { CommandBus } from '@nestjs/cqrs';

import {
    AddUserCommand,
    AddUsersCommand,
    BlockIpsCommand,
    CollectReportsCommand,
    DropIpsCommand,
    DropUsersConnectionsCommand,
    GetCombinedStatsCommand,
    GetNodeHealthCheckCommand,
    GetSystemStatsCommand,
    GetUserIpListCommand,
    GetUsersIpListCommand,
    GetUsersStatsCommand,
    RecreateTablesCommand,
    RemoveUserCommand,
    RemoveUsersCommand,
    StartXrayCommand,
    StopXrayCommand,
    SyncCommand,
    UnblockIpsCommand,
} from '@remnawave/node-contract';

import { prettyBytesUtil } from '@common/utils/bytes';
import { formatExecutionTime, getTime } from '@common/utils/get-elapsed-time';

import { GetNodeJwtCommand } from '@modules/keygen/commands/get-node-jwt';

import { fail, ok, TResult } from '../types';
import { INodeConnectionOpts, IMtlsOptions } from './axios.interfaces';
import { MtlsSocksProxyAgent } from './mtls-agent';

@Injectable()
export class AxiosService {
    private readonly logger = new Logger(AxiosService.name);

    public axiosInstance: AxiosInstance;
    private mtlsOptions: IMtlsOptions;
    private readonly socksAgentCache = new Map<string, MtlsSocksProxyAgent>();

    constructor(private readonly commandBus: CommandBus) {
        this.axiosInstance = axios.create({
            timeout: 45_000,
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
            },
        });
    }

    public async setJwt() {
        try {
            const result = await this.commandBus.execute(new GetNodeJwtCommand());

            if (!result.isOk) {
                throw new Error(
                    'There are a problem with the JWT token. Please restart Remnawave.',
                );
            }

            const jwt = result.response;

            this.axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${jwt.jwtToken}`;

            this.mtlsOptions = {
                cert: jwt.clientCert,
                key: jwt.clientKey,
                ca: jwt.caCert,
            };

            const httpsAgent = new https.Agent({
                ...this.mtlsOptions,
                checkServerIdentity: () => undefined,
                rejectUnauthorized: true,
                keepAlive: true,
                minVersion: 'TLSv1.3',
            });

            this.axiosInstance.defaults.httpsAgent = httpsAgent;

            this.logger.log('Axios interceptor registered');
        } catch (error) {
            this.logger.error(`Error in onApplicationBootstrap: ${error}`);
            throw error;
        }
    }

    private resolveAgentAndUrl(
        path: string,
        opts: INodeConnectionOpts,
    ): { httpsAgent: https.Agent; url: string } {
        const url = this.getNodeUrl(opts.address, path, opts.port);
        if (!opts.proxyUrl) {
            return {
                httpsAgent: this.axiosInstance.defaults.httpsAgent as https.Agent,
                url,
            };
        }

        const cached = this.socksAgentCache.get(opts.proxyUrl);
        if (cached)
            return {
                httpsAgent: cached,
                url,
            };

        const httpsAgent = new MtlsSocksProxyAgent(opts.proxyUrl, this.mtlsOptions);
        this.socksAgentCache.set(opts.proxyUrl, httpsAgent);
        return { httpsAgent, url };
    }

    private getNodeUrl(url: string, path: string, port: null | number): string {
        const protocol = 'https';
        const portSuffix = port ? `:${port}` : '';

        return `${protocol}://${url}${portSuffix}${path}`;
    }

    /*
     * XRAY MANAGEMENT
     */

    public async startXray(
        data: StartXrayCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<StartXrayCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(StartXrayCommand.url, opts);

        try {
            const startTime = getTime();
            const compressedData = await this.compressData(data);

            this.logger.log(
                `[ZSTD] [START XRAY] ${formatExecutionTime(startTime)} | ${prettyBytesUtil(compressedData.length)}`,
            );

            const response = await this.axiosInstance.post<StartXrayCommand.Response>(
                url,
                compressedData,
                {
                    timeout: 60_000,
                    headers: {
                        'Content-Encoding': 'zstd',
                    },
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                // this.logger.error(
                //     'Error in Axios StartXray Request:',
                //     JSON.stringify(error.message),
                // );

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in Axios StartXray Request:', error);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error)));
            }
        }
    }

    public async stopXray(opts: INodeConnectionOpts): Promise<TResult<StopXrayCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(StopXrayCommand.url, opts);
        try {
            const response = await this.axiosInstance.get<StopXrayCommand.Response>(url, {
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(
                    'Error in Axios StopXray Request:',
                    JSON.stringify(error.message),
                );

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in Axios StopXray Request:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async getNodeHealth(
        opts: INodeConnectionOpts,
    ): Promise<TResult<GetNodeHealthCheckCommand.Response['response']>> {
        try {
            const { url, httpsAgent } = this.resolveAgentAndUrl(
                GetNodeHealthCheckCommand.url,
                opts,
            );
            const { data } = await this.axiosInstance.get<GetNodeHealthCheckCommand.Response>(url, {
                timeout: 15_000,
                httpsAgent,
            });

            return ok(data.response);
        } catch (error) {
            if (error instanceof AxiosError) {
                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in Axios getNodeHealth:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    /*
     * STATS MANAGEMENT
     */

    public async getUsersStats(
        data: GetUsersStatsCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<GetUsersStatsCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(GetUsersStatsCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<GetUsersStatsCommand.Response>(
                url,
                data,
                {
                    timeout: 15_000,
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(
                    `Error in Axios getUsersStats: ${error.message}, JSON: ${JSON.stringify(error.response?.data)}`,
                );

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in getUsersStats:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async getIpsList(
        data: GetUserIpListCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<GetUserIpListCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(GetUserIpListCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<GetUserIpListCommand.Response>(
                url,
                data,
                {
                    timeout: 5_000,
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in getIpsList:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async getUsersIpsList(
        opts: INodeConnectionOpts,
    ): Promise<TResult<GetUsersIpListCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(GetUsersIpListCommand.url, opts);

        try {
            const response = await this.axiosInstance.get<GetUsersIpListCommand.Response>(
                url,

                {
                    timeout: 10_000,
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in getUsersIpsList:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async getSystemStats(
        opts: INodeConnectionOpts,
    ): Promise<TResult<GetSystemStatsCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(GetSystemStatsCommand.url, opts);

        try {
            const response = await this.axiosInstance.get<GetSystemStatsCommand.Response>(url, {
                timeout: 15_000,
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                // this.logger.error(`Error in axios request: ${JSON.stringify(error.message)}`);

                if (error.code === '500') {
                    return fail(
                        ERRORS.NODE_ERROR_500_WITH_MSG.withMessage(JSON.stringify(error.message)),
                    );
                }

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in getSystemStats:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async getCombinedStats(
        data: GetCombinedStatsCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<GetCombinedStatsCommand.Response['response']>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(GetCombinedStatsCommand.url, opts);

        try {
            const nodeResult = await this.axiosInstance.post<GetCombinedStatsCommand.Response>(
                url,
                data,
                {
                    httpsAgent,
                },
            );

            return ok(nodeResult.data.response);
        } catch (error) {
            if (error instanceof AxiosError) {
                if (error.code === '500') {
                    return fail(
                        ERRORS.NODE_ERROR_500_WITH_MSG.withMessage(JSON.stringify(error.message)),
                    );
                }

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in getAllInboundStats:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    /*
     * User management
     */

    public async addUser(
        data: AddUserCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<AddUserCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(AddUserCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<AddUserCommand.Response>(url, data, {
                timeout: 20_000,
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in addUser:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async deleteUser(
        data: RemoveUserCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<RemoveUserCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(RemoveUserCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<RemoveUserCommand.Response>(url, data, {
                timeout: 20_000,
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error('Error in deleteUser:', error.response?.data);
            } else {
                this.logger.error('Error in deleteUser:', error);
            }

            return fail(ERRORS.INTERNAL_SERVER_ERROR);
        }
    }

    public async addUsers(
        data: AddUsersCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<AddUsersCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(AddUsersCommand.url, opts);

        try {
            const startTime = getTime();
            const compressedData = await this.compressData(data);

            this.logger.log(
                `[ZSTD] [ADD USERS] ${formatExecutionTime(startTime)} | ${prettyBytesUtil(compressedData.length)}`,
            );

            const response = await this.axiosInstance.post<AddUsersCommand.Response>(
                url,
                compressedData,
                {
                    timeout: 20_000,
                    headers: {
                        'Content-Encoding': 'zstd',
                    },
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in addUser:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async deleteUsers(
        data: RemoveUsersCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<RemoveUsersCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(RemoveUsersCommand.url, opts);

        try {
            const startTime = getTime();
            const compressedData = await this.compressData(data);

            this.logger.log(
                `[ZSTD] [DELETE USERS] ${formatExecutionTime(startTime)} | ${prettyBytesUtil(compressedData.length)}`,
            );

            const response = await this.axiosInstance.post<RemoveUsersCommand.Response>(
                url,
                compressedData,
                {
                    timeout: 20_000,
                    headers: {
                        'Content-Encoding': 'zstd',
                    },
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error('Error in deleteUser:', error.response?.data);
            } else {
                this.logger.error('Error in deleteUser:', error);
            }

            return fail(ERRORS.INTERNAL_SERVER_ERROR);
        }
    }

    public async dropUsersConnections(
        data: DropUsersConnectionsCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<DropUsersConnectionsCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(DropUsersConnectionsCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<DropUsersConnectionsCommand.Response>(
                url,
                data,
                {
                    timeout: 10_000,
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios dropUsersConnections request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in dropUsersConnections:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async dropIpsConnections(
        data: DropIpsCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<DropIpsCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(DropIpsCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<DropIpsCommand.Response>(url, data, {
                timeout: 10_000,
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios dropIpsConnections request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in dropIpsConnections:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async syncNodePlugins(
        data: SyncCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<SyncCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(SyncCommand.url, opts);

        try {
            const startTime = getTime();
            const compressedData = await this.compressData(data);

            this.logger.log(
                `[ZSTD] [SYNC-NODE-PLUGINS] ${formatExecutionTime(startTime)} | ${prettyBytesUtil(compressedData.length)}`,
            );

            const response = await this.axiosInstance.post<SyncCommand.Response>(
                url,
                compressedData,
                {
                    timeout: 10_000,
                    headers: {
                        'Content-Encoding': 'zstd',
                    },
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in Axios SyncNodePlugins Request:', error);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error)));
            }
        }
    }

    public async collectTorrentBlockerReports(
        opts: INodeConnectionOpts,
    ): Promise<TResult<CollectReportsCommand.Response['response']>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(CollectReportsCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<CollectReportsCommand.Response>(
                url,
                {},
                {
                    timeout: 20_000,
                    httpsAgent,
                },
            );

            return ok(response.data.response);
        } catch (error) {
            if (error instanceof AxiosError) {
                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in Axios CollectTorrentBlockerReports Request:', error);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error)));
            }
        }
    }

    public async blockIps(
        data: BlockIpsCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<BlockIpsCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(BlockIpsCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<BlockIpsCommand.Response>(url, data, {
                timeout: 10_000,
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios blockIps request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in blockIps:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async unblockIps(
        data: UnblockIpsCommand.Request,
        opts: INodeConnectionOpts,
    ): Promise<TResult<UnblockIpsCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(UnblockIpsCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<UnblockIpsCommand.Response>(url, data, {
                timeout: 10_000,
                httpsAgent,
            });

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios unblockIps request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in unblockIps:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    public async recreateTables(
        opts: INodeConnectionOpts,
    ): Promise<TResult<RecreateTablesCommand.Response>> {
        const { url, httpsAgent } = this.resolveAgentAndUrl(RecreateTablesCommand.url, opts);

        try {
            const response = await this.axiosInstance.post<RecreateTablesCommand.Response>(
                url,
                {},
                {
                    timeout: 10_000,
                    httpsAgent,
                },
            );

            return ok(response.data);
        } catch (error) {
            if (error instanceof AxiosError) {
                this.logger.error(`Error in axios recreateTables request: ${error.message}`);

                return fail(ERRORS.NODE_ERROR_WITH_MSG.withMessage(JSON.stringify(error.message)));
            } else {
                this.logger.error('Error in recreateTables:', error);

                return fail(
                    ERRORS.NODE_ERROR_WITH_MSG.withMessage(
                        JSON.stringify(error) ?? 'Unknown error',
                    ),
                );
            }
        }
    }

    private async compressData(data: any): Promise<Buffer> {
        return await compress(Buffer.from(JSON.stringify(data)), 1);
    }
}
