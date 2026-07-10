import { z } from 'zod';

import { SUBSCRIPTION_TEMPLATE_TYPE } from '../constants';
import { ALPN, MIHOMO_IP_VERSION, SECURITY_LAYERS } from '../constants/hosts';

export const HostsSchema = z.object({
    uuid: z.string().uuid(),
    viewPosition: z.number().int(),
    remark: z.string(),
    address: z.string(),
    port: z.number().int(),
    path: z.string().nullable(),
    sni: z.string().nullable(),
    host: z.string().nullable(),
    alpn: z.nativeEnum(ALPN).nullable(),
    fingerprint: z.string().nullable(),
    isDisabled: z.boolean(),
    securityLayer: z.nativeEnum(SECURITY_LAYERS).default(SECURITY_LAYERS.DEFAULT),
    xhttpExtraParams: z.nullable(z.unknown()),
    muxParams: z.nullable(z.unknown()),
    sockoptParams: z.nullable(z.unknown()),
    finalMask: z.nullable(z.unknown()),

    inbound: z.object({
        configProfileUuid: z.string().uuid().nullable(),
        configProfileInboundUuid: z.string().uuid().nullable(),
    }),

    serverDescription: z.string().max(30).nullable(),
    tags: z.array(z.string()).default([]),
    isHidden: z.boolean().default(false),
    overrideSniFromAddress: z.boolean().default(false),
    keepSniBlank: z.boolean().default(false),
    vlessRouteId: z.number().int().min(0).max(65535).nullable(),
    pinnedPeerCertSha256: z.string().nullable(),
    verifyPeerCertByName: z.string().nullable(),
    shuffleHost: z.boolean(),
    mihomoX25519: z.boolean(),
    mihomoIpVersion: z.nativeEnum(MIHOMO_IP_VERSION).nullable(),

    nodes: z.array(z.string().uuid()),
    xrayJsonTemplateUuid: z.string().uuid().nullable(),
    excludedInternalSquads: z.array(z.string().uuid()),
    excludeFromSubscriptionTypes: z.array(z.nativeEnum(SUBSCRIPTION_TEMPLATE_TYPE)),
});
