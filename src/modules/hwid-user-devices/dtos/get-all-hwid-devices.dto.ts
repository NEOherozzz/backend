import { GetAllHwidDevicesCommand } from '@contract/commands';
import { createZodDto } from 'nestjs-zod';

export class GetAllHwidDevicesRequestQueryDto extends createZodDto(
    GetAllHwidDevicesCommand.RequestQuerySchema,
) {}

export class GetAllHwidDevicesResponseDto extends createZodDto(
    GetAllHwidDevicesCommand.ResponseSchema,
) {}
