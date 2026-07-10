import { z } from 'zod';

export const ApiTokensSchema = z.object({
    uuid: z.string().uuid(),
    name: z.string(),
    expireAt: z
        .string()
        .datetime()
        .transform((str) => new Date(str)),
    scopes: z.array(z.string()),
    createdAt: z
        .string()
        .datetime()
        .transform((str) => new Date(str)),
    updatedAt: z
        .string()
        .datetime()
        .transform((str) => new Date(str)),
});
