import { createZodDto } from 'nestjs-zod';

import {
    BulkDisableHostsCommand,
    BulkEnableHostsCommand,
    BulkDeleteHostsCommand,
    UpdateManyHostsCommand,
} from '@libs/contracts/commands';

export class BulkDeleteHostsRequestDto extends createZodDto(BulkDeleteHostsCommand.RequestSchema) {}
export class BulkDeleteHostsResponseDto extends createZodDto(
    BulkDeleteHostsCommand.ResponseSchema,
) {}

export class BulkDisableHostsRequestDto extends createZodDto(
    BulkDisableHostsCommand.RequestSchema,
) {}
export class BulkDisableHostsResponseDto extends createZodDto(
    BulkDisableHostsCommand.ResponseSchema,
) {}

export class BulkEnableHostsRequestDto extends createZodDto(BulkEnableHostsCommand.RequestSchema) {}
export class BulkEnableHostsResponseDto extends createZodDto(
    BulkEnableHostsCommand.ResponseSchema,
) {}

export class UpdateManyHostsRequestDto extends createZodDto(UpdateManyHostsCommand.RequestSchema) {}
export class UpdateManyHostsResponseDto extends createZodDto(
    UpdateManyHostsCommand.ResponseSchema,
) {}
