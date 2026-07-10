import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { SCOPE_ENDPOINT, SCOPE_RESOURCE } from '@common/decorators/scopes';
import {
    buildActionScope,
    buildEndpointScope,
    buildResourceScope,
    EndpointDetails,
    ROLE,
    SCOPE_WILDCARD,
} from '@libs/contracts/constants';

import { IJWTAuthPayload } from '@modules/auth/interfaces';

@Injectable()
export class ScopesGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) {}

    canActivate(context: ExecutionContext): boolean {
        const resource = this.reflector.getAllAndOverride<string | undefined>(SCOPE_RESOURCE, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!resource) return true;

        const request = context.switchToHttp().getRequest<{ user: IJWTAuthPayload }>();

        if (!request.user) return false;
        if (request.user.role === ROLE.ADMIN) return true;

        const scopes = request.user.scopes ?? [];
        if (scopes.length === 0) return false;
        if (scopes.includes(SCOPE_WILDCARD)) return true;

        if (scopes.includes(buildResourceScope(resource))) {
            return true;
        }

        const details = this.reflector.get<EndpointDetails | undefined>(
            SCOPE_ENDPOINT,
            context.getHandler(),
        );

        if (!details) {
            return false;
        }

        if (details.SCOPE_KIND && scopes.includes(buildActionScope(resource, details.SCOPE_KIND))) {
            return true;
        }

        if (details.SCOPE && scopes.includes(buildEndpointScope(resource, details.SCOPE))) {
            return true;
        }

        return false;
    }
}
