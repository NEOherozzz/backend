import { ResetNodeTrafficCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class ResetNodeTrafficRequestDto extends createZodDto(
    ResetNodeTrafficCommand.RequestSchema,
) {}
export class ResetNodeTrafficResponseDto extends createZodDto(
    ResetNodeTrafficCommand.ResponseSchema,
) {}
