import { Body, Controller, HttpStatus, Param, UseFilters, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';

import { Endpoint } from '@common/decorators/base-endpoint';
import { Roles } from '@common/decorators/roles/roles';
import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards/def-jwt-guard';
import { RolesGuard } from '@common/guards/roles';
import { errorHandler } from '@common/helpers/error-handler.helper';
import { API_TOKENS_CONTROLLER, CONTROLLERS_INFO } from '@libs/contracts/api';
import {
    CreateApiTokenCommand,
    DeleteApiTokenCommand,
    FindAllApiTokensCommand,
    GetApiTokenScopesCommand,
} from '@libs/contracts/commands';
import { ROLE } from '@libs/contracts/constants';

import { ApiTokensService } from './api-tokens.service';
import {
    CreateApiTokenRequestDto,
    CreateApiTokenResponseDto,
    DeleteApiTokenRequestDto,
    DeleteApiTokenResponseDto,
    FindAllApiTokensResponseDto,
    GetApiTokenScopesResponseDto,
} from './dtos';

@ApiBearerAuth('Authorization')
@ApiTags(CONTROLLERS_INFO.API_TOKENS.tag)
@Roles(ROLE.ADMIN)
@UseGuards(JwtDefaultGuard, RolesGuard)
@UseFilters(HttpExceptionFilter)
@Controller(API_TOKENS_CONTROLLER)
export class ApiTokensController {
    constructor(private readonly apiTokensService: ApiTokensService) {}

    @ApiResponse({
        status: 201,
        description: 'Token created successfully',
        type: CreateApiTokenResponseDto,
    })
    @Endpoint({
        command: CreateApiTokenCommand,
        httpCode: HttpStatus.CREATED,
        apiBody: CreateApiTokenRequestDto,
    })
    async create(@Body() body: CreateApiTokenRequestDto): Promise<CreateApiTokenResponseDto> {
        const result = await this.apiTokensService.create(body);

        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @ApiParam({ name: 'uuid', type: String, description: 'UUID of the API token' })
    @ApiResponse({
        status: 200,
        description: 'Token deleted successfully',
        type: DeleteApiTokenResponseDto,
    })
    @Endpoint({
        command: DeleteApiTokenCommand,
        httpCode: HttpStatus.OK,
    })
    async delete(@Param() paramData: DeleteApiTokenRequestDto): Promise<DeleteApiTokenResponseDto> {
        const result = await this.apiTokensService.delete(paramData.uuid);
        const data = errorHandler(result);
        return {
            response: data.result,
        };
    }

    @ApiResponse({
        status: 200,
        description: 'Available API token scopes fetched successfully',
        type: GetApiTokenScopesResponseDto,
    })
    @Endpoint({
        command: GetApiTokenScopesCommand,
        httpCode: HttpStatus.OK,
    })
    async getScopes(): Promise<GetApiTokenScopesResponseDto> {
        const result = this.apiTokensService.getAvailableScopes();
        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @ApiResponse({
        status: 200,
        description: 'Tokens fetched successfully',
        type: FindAllApiTokensResponseDto,
    })
    @Endpoint({
        command: FindAllApiTokensCommand,
        httpCode: HttpStatus.OK,
    })
    async findAll(): Promise<FindAllApiTokensResponseDto> {
        const result = await this.apiTokensService.findAll();
        const data = errorHandler(result);
        return {
            response: data,
        };
    }
}
