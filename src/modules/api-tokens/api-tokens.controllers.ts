import { Body, Controller, HttpStatus, Param, UseFilters, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiExcludeEndpoint, ApiTags } from '@nestjs/swagger';

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
    GetApiTokensCommand,
    GetApiTokenScopesCommand,
    GetOttCommand,
} from '@libs/contracts/commands';
import { ROLE } from '@libs/contracts/constants';

import { ApiTokensService } from './api-tokens.service';
import {
    CreateApiTokenBodyDto,
    CreateApiTokenResponseDto,
    DeleteApiTokenParamDto,
    GetApiTokensResponseDto,
    GetApiTokenScopesResponseDto,
    GetOttResponseDto,
} from './dtos';

@ApiBearerAuth('Authorization')
@ApiTags(CONTROLLERS_INFO.API_TOKENS.tag)
@Roles(ROLE.ADMIN)
@UseGuards(JwtDefaultGuard, RolesGuard)
@UseFilters(HttpExceptionFilter)
@Controller(API_TOKENS_CONTROLLER)
export class ApiTokensController {
    constructor(private readonly apiTokensService: ApiTokensService) {}

    @Endpoint({
        command: CreateApiTokenCommand,
        httpCode: HttpStatus.CREATED,
        type: CreateApiTokenResponseDto,
    })
    async createApiToken(@Body() body: CreateApiTokenBodyDto): Promise<CreateApiTokenResponseDto> {
        const result = await this.apiTokensService.create(body);

        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: DeleteApiTokenCommand,
        httpCode: HttpStatus.NO_CONTENT,
    })
    async deleteApiToken(@Param() param: DeleteApiTokenParamDto) {
        const result = await this.apiTokensService.delete(param.uuid);

        errorHandler(result);
        return;
    }

    @Endpoint({
        command: GetApiTokenScopesCommand,
        httpCode: HttpStatus.OK,
        type: GetApiTokenScopesResponseDto,
    })
    async getScopes(): Promise<GetApiTokenScopesResponseDto> {
        const result = this.apiTokensService.getAvailableScopes();
        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: GetApiTokensCommand,
        httpCode: HttpStatus.OK,
        type: GetApiTokensResponseDto,
    })
    async getApiTokens(): Promise<GetApiTokensResponseDto> {
        const result = await this.apiTokensService.get();
        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @ApiExcludeEndpoint()
    @Endpoint({
        command: GetOttCommand,
        httpCode: HttpStatus.OK,
        type: GetOttResponseDto,
    })
    async getOtt(): Promise<GetOttResponseDto> {
        const result = await this.apiTokensService.getOtt();

        const data = errorHandler(result);
        return {
            response: data,
        };
    }
}
