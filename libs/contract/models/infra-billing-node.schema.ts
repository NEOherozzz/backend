import { z } from 'zod';

import { PartialInfraProviderSchema } from './infra-provider.schema';
import { NodesSchema } from './nodes.schema';

export const InfraBillingNodeSchema = z.object({
    uuid: z.string().uuid(),
    nodeUuid: z.string().uuid().nullable(),
    name: z.string().nullable(),
    providerUuid: z.string().uuid(),
    provider: PartialInfraProviderSchema.pick({
        uuid: true,
        name: true,
        loginUrl: true,
        faviconLink: true,
    }),

    node: NodesSchema.pick({
        uuid: true,
        name: true,
        countryCode: true,
    }).nullable(),

    nextBillingAt: z
        .string()
        .datetime()
        .transform((str) => new Date(str)),

    createdAt: z
        .string()
        .datetime()
        .transform((str) => new Date(str)),
    updatedAt: z
        .string()
        .datetime()
        .transform((str) => new Date(str)),
});
