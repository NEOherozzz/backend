import { Body, Controller, HttpStatus, Param, Query, UseFilters, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

import { Endpoint } from '@common/decorators/base-endpoint';
import { Roles } from '@common/decorators/roles/roles';
import { ApiScopeResource } from '@common/decorators/scopes';
import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards/def-jwt-guard';
import { RolesGuard } from '@common/guards/roles';
import { ScopesGuard } from '@common/guards/scopes';
import { errorHandler } from '@common/helpers/error-handler.helper';
import { CONTROLLERS_INFO, HWID_CONTROLLER } from '@libs/contracts/api';
import {
    CreateUserHwidDeviceCommand,
    DeleteAllUserHwidDevicesCommand,
    DeleteUserHwidDeviceCommand,
    GetHwidDevicesCommand,
    GetHwidDevicesStatsCommand,
    GetTopUsersByHwidDevicesCommand,
    GetUserHwidDevicesCommand,
} from '@libs/contracts/commands';
import { ROLE } from '@libs/contracts/constants';

import {
    CreateUserHwidDeviceBodyDto,
    CreateUserHwidDeviceResponseDto,
    DeleteAllUserHwidDevicesBodyDto,
    DeleteAllUserHwidDevicesResponseDto,
    DeleteUserHwidDeviceBodyDto,
    DeleteUserHwidDeviceResponseDto,
    GetHwidDevicesQueryDto,
    GetHwidDevicesQueryResponseDto,
    GetHwidDevicesStatsResponseDto,
    GetTopUsersByHwidDevicesQueryDto,
    GetTopUsersByHwidDevicesResponseDto,
    GetUserHwidDevicesParamDto,
    GetUserHwidDevicesResponseDto,
} from './dtos';
import { HwidUserDevicesService } from './hwid-user-devices.service';
import { BaseUserHwidDevicesResponseModel, GetAllHwidDevicesResponseModel } from './models';

@ApiBearerAuth('Authorization')
@ApiScopeResource(CONTROLLERS_INFO.HWID_USER_DEVICES.resource)
@ApiTags(CONTROLLERS_INFO.HWID_USER_DEVICES.tag)
@Roles(ROLE.ADMIN, ROLE.API)
@UseGuards(JwtDefaultGuard, RolesGuard, ScopesGuard)
@UseFilters(HttpExceptionFilter)
@Controller(HWID_CONTROLLER)
export class HwidUserDevicesController {
    constructor(private readonly hwidUserDevicesService: HwidUserDevicesService) {}

    @Endpoint({
        command: GetHwidDevicesCommand,
        httpCode: HttpStatus.OK,
        type: GetHwidDevicesQueryResponseDto,
    })
    async getAllUsers(
        @Query() query: GetHwidDevicesQueryDto,
    ): Promise<GetHwidDevicesQueryResponseDto> {
        const { start, size, filters, filterModes, globalFilterMode, sorting } = query;
        const result = await this.hwidUserDevicesService.getAllHwidDevices({
            start,
            size,
            filters,
            filterModes,
            globalFilterMode,
            sorting,
        });

        const data = errorHandler(result);
        return {
            response: new GetAllHwidDevicesResponseModel({
                total: data.total,
                devices: data.devices.map((item) => new BaseUserHwidDevicesResponseModel(item)),
            }),
        };
    }

    @Endpoint({
        command: CreateUserHwidDeviceCommand,
        httpCode: HttpStatus.OK,
        type: CreateUserHwidDeviceResponseDto,
    })
    async createUserHwidDevice(
        @Body() body: CreateUserHwidDeviceBodyDto,
    ): Promise<CreateUserHwidDeviceResponseDto> {
        const result = await this.hwidUserDevicesService.createUserHwidDevice(body);

        const data = errorHandler(result);
        return {
            response: {
                total: data.length,
                devices: data.map((item) => new BaseUserHwidDevicesResponseModel(item)),
            },
        };
    }

    @Endpoint({
        command: DeleteUserHwidDeviceCommand,
        httpCode: HttpStatus.OK,
        type: DeleteUserHwidDeviceResponseDto,
    })
    async deleteUserHwidDevice(
        @Body() body: DeleteUserHwidDeviceBodyDto,
    ): Promise<DeleteUserHwidDeviceResponseDto> {
        const result = await this.hwidUserDevicesService.deleteUserHwidDevice(
            body.hwid,
            body.userId,
        );

        const data = errorHandler(result);
        return {
            response: {
                total: data.length,
                devices: data.map((item) => new BaseUserHwidDevicesResponseModel(item)),
            },
        };
    }

    @Endpoint({
        command: DeleteAllUserHwidDevicesCommand,
        httpCode: HttpStatus.OK,
        type: DeleteAllUserHwidDevicesResponseDto,
    })
    async deleteAllUserHwidDevices(
        @Body() body: DeleteAllUserHwidDevicesBodyDto,
    ): Promise<DeleteAllUserHwidDevicesResponseDto> {
        const result = await this.hwidUserDevicesService.deleteAllUserHwidDevices(body.userId);

        const data = errorHandler(result);
        return {
            response: {
                total: data.length,
                devices: data.map((item) => new BaseUserHwidDevicesResponseModel(item)),
            },
        };
    }

    @Endpoint({
        command: GetHwidDevicesStatsCommand,
        httpCode: HttpStatus.OK,
        type: GetHwidDevicesStatsResponseDto,
    })
    async getHwidDevicesStats(): Promise<GetHwidDevicesStatsResponseDto> {
        const result = await this.hwidUserDevicesService.getHwidDevicesStats();

        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: GetTopUsersByHwidDevicesCommand,
        httpCode: HttpStatus.OK,
        type: GetTopUsersByHwidDevicesResponseDto,
    })
    async getTopUsersByHwidDevices(
        @Query() query: GetTopUsersByHwidDevicesQueryDto,
    ): Promise<GetTopUsersByHwidDevicesResponseDto> {
        const { start, size } = query;
        const result = await this.hwidUserDevicesService.getTopUsersByHwidDevices({
            start,
            size,
        });

        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: GetUserHwidDevicesCommand,
        httpCode: HttpStatus.OK,
        type: GetUserHwidDevicesResponseDto,
    })
    async getUserHwidDevices(
        @Param() params: GetUserHwidDevicesParamDto,
    ): Promise<GetUserHwidDevicesResponseDto> {
        const result = await this.hwidUserDevicesService.getUserHwidDevices(params.userId);

        const data = errorHandler(result);
        return {
            response: {
                total: data.length,
                devices: data.map((item) => new BaseUserHwidDevicesResponseModel(item)),
            },
        };
    }
}
