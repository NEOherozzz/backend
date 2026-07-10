import { DeleteUserHwidDeviceCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class DeleteUserHwidDeviceRequestDto extends createZodDto(
    DeleteUserHwidDeviceCommand.RequestSchema,
) {}

export class DeleteUserHwidDeviceResponseDto extends createZodDto(
    DeleteUserHwidDeviceCommand.ResponseSchema,
) {}
