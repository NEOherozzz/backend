import { ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { QueryBus } from '@nestjs/cqrs';
import { AuthGuard } from '@nestjs/passport';

import { RawCacheService } from '@common/raw-cache';
import { TResult } from '@common/types';
import {
    REMNAWAVE_CLIENT_TYPE_BROWSER,
    REMNAWAVE_CLIENT_TYPE_HEADER,
    ROLE,
} from '@libs/contracts/constants';

import { AdminEntity } from '@modules/admin/entities/admin.entity';
import { GetAdminByUsernameQuery } from '@modules/admin/queries/get-admin-by-username';
import { ApiTokenEntity } from '@modules/api-tokens/entities/api-token.entity';
import { GetTokenByUuidQuery } from '@modules/api-tokens/queries/get-token-by-uuid';
import { IJWTAuthPayload } from '@modules/auth/interfaces';

@Injectable()
export class JwtDefaultGuard extends AuthGuard('registeredUserJWT') {
    constructor(
        private readonly rawCacheService: RawCacheService,
        private readonly queryBus: QueryBus,
    ) {
        super();
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isJwtValid = await super.canActivate(context);
        if (!isJwtValid) {
            return false;
        }

        const { user } = context.switchToHttp().getRequest<{ user: IJWTAuthPayload }>();

        if (!user || !user.role || !user.uuid) {
            return false;
        }

        switch (user.role) {
            case ROLE.API: {
                return await this.verifyApiToken(user, user.uuid);
            }

            case ROLE.ADMIN: {
                const headers = context.switchToHttp().getRequest().headers;

                const clientType = headers[REMNAWAVE_CLIENT_TYPE_HEADER.toLowerCase()];

                if (clientType !== REMNAWAVE_CLIENT_TYPE_BROWSER) {
                    throw new ForbiddenException(
                        'For API requests you must create own API-token in the admin dashboard.',
                    );
                }

                if (!user.username) {
                    return false;
                }

                const adminEntity = await this.getAdminByUsername({
                    username: user.username,
                    role: user.role,
                });

                if (!adminEntity.isOk) {
                    return false;
                }

                if (adminEntity.response.uuid !== user.uuid) {
                    return false;
                }
                return true;
            }
            default:
                return false;
        }
    }

    private async getAdminByUsername(dto: GetAdminByUsernameQuery): Promise<TResult<AdminEntity>> {
        return this.queryBus.execute<GetAdminByUsernameQuery, TResult<AdminEntity>>(
            new GetAdminByUsernameQuery(dto.username, dto.role),
        );
    }

    private async getTokenByUuid(dto: GetTokenByUuidQuery): Promise<TResult<ApiTokenEntity>> {
        return this.queryBus.execute<GetTokenByUuidQuery, TResult<ApiTokenEntity>>(
            new GetTokenByUuidQuery(dto.uuid),
        );
    }

    private async verifyApiToken(user: IJWTAuthPayload, apiTokenUuid: string): Promise<boolean> {
        const cached = await this.rawCacheService.get<string[]>(`api:${apiTokenUuid}`);
        if (cached) {
            user.scopes = cached;
            return true;
        }

        const token = await this.getTokenByUuid({ uuid: apiTokenUuid });
        if (!token.isOk) {
            return false;
        }

        const scopes = token.response.scopes ?? [];

        await this.rawCacheService.set(`api:${apiTokenUuid}`, scopes, 3600);
        user.scopes = scopes;
        return true;
    }
}
