import { z } from 'zod';

import { HOSTS_ROUTES, REST_API } from '../../api';
import {
    getEndpointDetails,
    SECURITY_LAYERS,
    ALPN,
    SUBSCRIPTION_TEMPLATE_TYPE,
    MIHOMO_IP_VERSION,
} from '../../constants';
import { HostsSchema } from '../../models';

export namespace UpdateHostCommand {
    export const url = REST_API.HOSTS.UPDATE;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        HOSTS_ROUTES.UPDATE,
        'patch',
        'Update a host',
        { scope: 'update', kind: 'write' },
    );

    export const RequestSchema = HostsSchema.pick({
        uuid: true,
    }).extend({
        inbound: z
            .object({
                configProfileUuid: z.string().uuid(),
                configProfileInboundUuid: z.string().uuid(),
            })
            .optional(),
        remark: z
            .string({
                invalid_type_error: 'Remark must be a string',
            })
            .max(40, {
                message: 'Remark must be less than 40 characters',
            })
            .optional(),
        address: z
            .string({
                invalid_type_error: 'Address must be a string',
            })
            .optional(),
        port: z
            .number({
                invalid_type_error: 'Port must be an integer',
            })
            .int()
            .optional(),
        path: z.string().nullish(),
        sni: z.string().nullish(),
        host: z.string().nullish(),
        alpn: z.nativeEnum(ALPN).nullish(),
        fingerprint: z.string().nullish(),
        isDisabled: z.boolean().default(false),
        securityLayer: z.optional(z.nativeEnum(SECURITY_LAYERS)),
        xhttpExtraParams: z.unknown().nullish(),
        muxParams: z.unknown().nullish(),
        sockoptParams: z.unknown().nullish(),
        finalMask: z.unknown().nullish(),
        serverDescription: z
            .string()
            .max(30, {
                message: 'Server description must be less than 30 characters',
            })
            .nullish(),
        tags: z.optional(
            z
                .array(
                    z
                        .string()
                        .regex(
                            /^[A-Z0-9_:]+$/,
                            'Tag can only contain uppercase letters, numbers, underscores and colons',
                        )
                        .max(36, 'Each tag must be less than 36 characters'),
                )
                .max(10, 'Maximum 10 tags'),
        ),
        isHidden: z.optional(z.boolean()),
        overrideSniFromAddress: z.optional(z.boolean()),
        keepSniBlank: z.optional(z.boolean()),
        vlessRouteId: z.optional(z.number().int().min(0).max(65535).nullable()),
        pinnedPeerCertSha256: z.string().nullish(),
        verifyPeerCertByName: z.string().nullish(),
        shuffleHost: z.optional(z.boolean()),
        mihomoX25519: z.optional(z.boolean()),
        mihomoIpVersion: z.nativeEnum(MIHOMO_IP_VERSION).nullish(),
        nodes: z.optional(z.array(z.string().uuid())),
        xrayJsonTemplateUuid: z.string().uuid().nullish(),
        excludedInternalSquads: z
            .optional(z.array(z.string().uuid()))
            .describe('Optional. Internal squads from which the host will be excluded.'),
        excludeFromSubscriptionTypes: z
            .optional(z.array(z.nativeEnum(SUBSCRIPTION_TEMPLATE_TYPE)))
            .describe('Optional. Subscription types from which the host will be excluded from.'),
    });
    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: HostsSchema,
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
