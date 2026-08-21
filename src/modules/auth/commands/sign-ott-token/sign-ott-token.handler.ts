import { CommandHandler, ICommandHandler } from '@nestjs/cqrs';
import { JwtService } from '@nestjs/jwt';

import { ok, TResult } from '@common/types';
import { BACKEND_TOOLS_JWT_ISSUER, BACKEND_TOOLS_JWT_SCOPES } from '@libs/contracts/constants';

import { SignOttTokenCommand } from './sign-ott-token.command';

interface IOttTokenPayload {
    scope: string;
}

@CommandHandler(SignOttTokenCommand)
export class SignOttTokenHandler implements ICommandHandler<SignOttTokenCommand, TResult<string>> {
    constructor(private readonly jwtService: JwtService) {}

    async execute(): Promise<TResult<string>> {
        const payload: IOttTokenPayload = {
            scope: BACKEND_TOOLS_JWT_SCOPES.OTT,
        };

        return ok(
            this.jwtService.sign(payload, {
                expiresIn: '30s',
                issuer: BACKEND_TOOLS_JWT_ISSUER,
            }),
        );
    }
}
