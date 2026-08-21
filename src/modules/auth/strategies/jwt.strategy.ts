import type { IJWTAuthPayload } from '../interfaces';

import { ExtractJwt, Strategy } from 'passport-jwt';

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';

import { TypedConfigService } from '@common/config/app-config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'registeredUserJWT') {
    constructor(configService: TypedConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.getOrThrow('APP_SECRET'),
        });
    }

    async validate(JWTPrivatePayload: IJWTAuthPayload): Promise<IJWTAuthPayload> {
        return JWTPrivatePayload;
    }
}
