import { GetUserHwidDevicesCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetUserHwidDevicesRequestDto extends createZodDto(
    GetUserHwidDevicesCommand.RequestSchema,
) {}

export class GetUserHwidDevicesResponseDto extends createZodDto(
    GetUserHwidDevicesCommand.ResponseSchema,
) {}
