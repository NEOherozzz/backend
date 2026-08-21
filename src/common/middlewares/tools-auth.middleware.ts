import { NextFunction, Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { getQuery } from 'ufo';

import { Logger } from '@nestjs/common';

import { HttpExceptionWithErrorCodeType } from '@common/exception/http-exeception-with-error-code.type';
import { isDevelopment } from '@common/utils/startup-app';
import { BACKEND_TOOLS_ROOT, ROOT } from '@libs/contracts/api';
import {
    BACKEND_TOOLS_AUTH_COOKIE_NAME,
    BACKEND_TOOLS_JWT_ISSUER,
    BACKEND_TOOLS_JWT_LIFETIME_HOURS,
    BACKEND_TOOLS_JWT_SCOPES,
    ERRORS,
    TBackendToolsJwtScope,
} from '@libs/contracts/constants';

const logger = new Logger('ToolsAuth');

export function toolsAuthMiddleware(appSecret: string) {
    return (req: Request, res: Response, next: NextFunction) => {
        const { ott } = getQuery(req.originalUrl);

        if (typeof ott === 'string' && ott.length > 0) {
            if (verifyJwt(ott, appSecret, 'ott')) {
                const token = signJwt(appSecret);

                res.cookie(BACKEND_TOOLS_AUTH_COOKIE_NAME, token, {
                    httpOnly: true,
                    secure: !isDevelopment(),
                    sameSite: 'lax',
                    path: `${ROOT}${BACKEND_TOOLS_ROOT}`,
                    maxAge: BACKEND_TOOLS_JWT_LIFETIME_HOURS * 3_600_000,
                });

                logger.warn(
                    `Tools access granted. Request: ${req.originalUrl}. IP: ${'clientIp' in req ? req.clientIp : 'unknown'}`,
                );

                const redirectUrl = new URL(req.originalUrl, 'http://localhost');
                redirectUrl.searchParams.delete('ott');
                res.redirect(redirectUrl.pathname + redirectUrl.search);

                return;
            } else {
                throw new HttpExceptionWithErrorCodeType(
                    ERRORS.FORBIDDEN.message,
                    ERRORS.FORBIDDEN.code,
                    ERRORS.FORBIDDEN.httpCode,
                );
            }
        }

        if (!hasValidCookie(req, appSecret)) {
            throw new HttpExceptionWithErrorCodeType(
                ERRORS.FORBIDDEN.message,
                ERRORS.FORBIDDEN.code,
                ERRORS.FORBIDDEN.httpCode,
            );
        }

        return next();
    };
}

function hasValidCookie(req: Request, appSecret: string): boolean {
    const token = getCookie(req, BACKEND_TOOLS_AUTH_COOKIE_NAME);

    if (!token) {
        return false;
    }

    return verifyJwt(token, appSecret, BACKEND_TOOLS_JWT_SCOPES.ACCESS);
}

function getCookie(req: Request, name: string): string | null {
    const header = req.headers.cookie;

    if (!header) {
        return null;
    }

    for (const part of header.split(';')) {
        const [key, ...rest] = part.trim().split('=');

        if (key === name) {
            return decodeURIComponent(rest.join('='));
        }
    }

    return null;
}

function signJwt(appSecret: string) {
    return jwt.sign({ scope: BACKEND_TOOLS_JWT_SCOPES.ACCESS }, appSecret, {
        expiresIn: `${BACKEND_TOOLS_JWT_LIFETIME_HOURS}h`,
        issuer: BACKEND_TOOLS_JWT_ISSUER,
    });
}

function verifyJwt(token: string, appSecret: string, scope: TBackendToolsJwtScope): boolean {
    try {
        const decoded = jwt.verify(token, appSecret, {
            issuer: BACKEND_TOOLS_JWT_ISSUER,
            ignoreExpiration: false,
        });

        return typeof decoded === 'object' && decoded.scope === scope;
    } catch {
        return false;
    }
}
