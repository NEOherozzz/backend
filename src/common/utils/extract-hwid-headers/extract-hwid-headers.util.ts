import { Request } from 'express';

import { truncateHeader } from '../truncate-header.util';

export interface HwidHeaders {
    hwid: string;
    platform?: string;
    osVersion?: string;
    deviceModel?: string;
    userAgent?: string;
}

const HWID_REGEX = /^[a-zA-Z0-9=-]{10,64}$/;

export function extractHwidHeaders(request: Request): HwidHeaders | null {
    const rawHwid = request.headers['x-hwid'];
    const hwid = Array.isArray(rawHwid) ? rawHwid[0] : rawHwid;

    if (!hwid || !HWID_REGEX.test(hwid)) {
        return null;
    }

    return {
        hwid,
        platform: truncateHeader(request.headers['x-device-os']),
        osVersion: truncateHeader(request.headers['x-ver-os']),
        deviceModel: truncateHeader(request.headers['x-device-model']),
        userAgent: truncateHeader(request.headers['user-agent']),
    };
}
