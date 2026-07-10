import { TestSrrMatcherCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class DebugSrrMatcherRequestDto extends createZodDto(TestSrrMatcherCommand.RequestSchema) {}

export class DebugSrrMatcherResponseDto extends createZodDto(
    TestSrrMatcherCommand.ResponseSchema,
) {}
