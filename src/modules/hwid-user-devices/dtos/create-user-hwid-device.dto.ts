import { CreateUserHwidDeviceCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class CreateUserHwidDeviceRequestDto extends createZodDto(
    CreateUserHwidDeviceCommand.RequestSchema,
) {}

export class CreateUserHwidDeviceResponseDto extends createZodDto(
    CreateUserHwidDeviceCommand.ResponseSchema,
) {}
