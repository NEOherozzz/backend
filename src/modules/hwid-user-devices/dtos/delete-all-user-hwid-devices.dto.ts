import { DeleteAllUserHwidDevicesCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class DeleteAllUserHwidDevicesRequestDto extends createZodDto(
    DeleteAllUserHwidDevicesCommand.RequestSchema,
) {}

export class DeleteAllUserHwidDevicesResponseDto extends createZodDto(
    DeleteAllUserHwidDevicesCommand.ResponseSchema,
) {}
