import { z } from 'zod';

import { REST_API, SYSTEM_ROUTES } from '../../../api';
import { getEndpointDetails, RESPONSE_RULES_RESPONSE_TYPES } from '../../../constants';
import { ResponseRuleSchema, ResponseRulesConfigSchema } from '../../../models';

export namespace TestSrrMatcherCommand {
    export const url = REST_API.SYSTEM.TESTERS.SRR_MATCHER;
    export const TSQ_url = url;

    export const endpointDetails = getEndpointDetails(
        SYSTEM_ROUTES.TESTERS.SRR_MATCHER,
        'post',
        'Test SRR Matcher',
        { scope: 'test-srr-matcher', kind: 'write' },
    );
    export const RequestSchema = z.object({
        responseRules: ResponseRulesConfigSchema,
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            matched: z.boolean(),
            responseType: z.nativeEnum(RESPONSE_RULES_RESPONSE_TYPES),
            matchedRule: z.nullable(ResponseRuleSchema),
            inputHeaders: z.record(z.string(), z.string()),
            outputHeaders: z.record(z.string(), z.string()),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
