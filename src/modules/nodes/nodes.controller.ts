import { CONTROLLERS_INFO, NODES_CONTROLLER } from '@contract/api';
import { ROLE } from '@contract/constants';

import { Body, Controller, HttpStatus, Param, UseFilters, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

import { Endpoint } from '@common/decorators/base-endpoint';
import { Roles } from '@common/decorators/roles/roles';
import { ApiScopeResource } from '@common/decorators/scopes';
import { HttpExceptionFilter } from '@common/exception/http-exception.filter';
import { JwtDefaultGuard } from '@common/guards/jwt-guards/def-jwt-guard';
import { RolesGuard } from '@common/guards/roles/roles.guard';
import { ScopesGuard } from '@common/guards/scopes';
import { errorHandler } from '@common/helpers/error-handler.helper';
import {
    CreateNodeCommand,
    DeleteNodeCommand,
    DisableNodeCommand,
    EnableNodeCommand,
    GetNodesCommand,
    GetNodesTagsCommand,
    GetNodeCommand,
    BulkNodesProfileModificationCommand,
    ReorderNodesCommand,
    ResetNodeTrafficCommand,
    RestartAllNodesCommand,
    RestartNodeCommand,
    UpdateNodeCommand,
    BulkNodesActionsCommand,
    BulkNodesUpdateCommand,
} from '@libs/contracts/commands';

import {
    BulkNodesActionsBodyDto,
    BulkNodesUpdateBodyDto,
    CreateNodeBodyDto,
    DeleteNodeParamDto,
    DisableNodeParamDto,
    GetNodesResponseDto,
    GetNodesTagsResponseDto,
    GetNodeParamDto,
    ProfileModificationBodyDto,
    ReorderNodesBodyDto,
    ResetNodeTrafficParamDto,
    RestartNodeParamDto,
    RestartNodeBodyDto,
    EnableNodeParamDto,
    UpdateNodeBodyDto,
    RestartAllNodesBodyDto,
    ReorderNodesResponseDto,
    NodeResponseDto,
} from './dtos';
import { GetAllNodesTagsResponseModel } from './models';
import { NodesService } from './nodes.service';

@ApiBearerAuth('Authorization')
@ApiScopeResource(CONTROLLERS_INFO.NODES.resource)
@ApiTags(CONTROLLERS_INFO.NODES.tag)
@Roles(ROLE.ADMIN, ROLE.API)
@UseGuards(JwtDefaultGuard, RolesGuard, ScopesGuard)
@UseFilters(HttpExceptionFilter)
@Controller(NODES_CONTROLLER)
export class NodesController {
    constructor(private readonly nodesService: NodesService) {}

    @Endpoint({
        type: GetNodesTagsResponseDto,
        command: GetNodesTagsCommand,
        httpCode: HttpStatus.OK,
    })
    async getNodesTags(): Promise<GetNodesTagsResponseDto> {
        const res = await this.nodesService.getAllNodesTags();
        const data = errorHandler(res);
        return {
            response: new GetAllNodesTagsResponseModel(data),
        };
    }

    @Endpoint({
        type: NodeResponseDto,
        command: CreateNodeCommand,
        httpCode: HttpStatus.CREATED,
    })
    async createNode(@Body() body: CreateNodeBodyDto): Promise<NodeResponseDto> {
        const result = await this.nodesService.createNode(body);

        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @Endpoint({
        type: GetNodesResponseDto,
        command: GetNodesCommand,
        httpCode: HttpStatus.OK,
    })
    async getNodes(): Promise<GetNodesResponseDto> {
        const res = await this.nodesService.getAllNodes();
        const data = errorHandler(res);
        return {
            response: data,
        };
    }

    @Endpoint({
        type: NodeResponseDto,
        command: GetNodeCommand,
        httpCode: HttpStatus.OK,
    })
    async getNode(@Param() uuid: GetNodeParamDto): Promise<NodeResponseDto> {
        const res = await this.nodesService.getOneNode(uuid.uuid);
        const data = errorHandler(res);
        return {
            response: data,
        };
    }

    @Endpoint({
        type: NodeResponseDto,
        command: EnableNodeCommand,
        httpCode: HttpStatus.OK,
    })
    async enableNode(@Param() param: EnableNodeParamDto): Promise<NodeResponseDto> {
        const res = await this.nodesService.enableNode(param.uuid);
        const data = errorHandler(res);
        return {
            response: data,
        };
    }

    @Endpoint({
        type: NodeResponseDto,
        command: DisableNodeCommand,
        httpCode: HttpStatus.OK,
    })
    async disableNode(@Param() param: DisableNodeParamDto): Promise<NodeResponseDto> {
        const res = await this.nodesService.disableNode(param.uuid);
        const data = errorHandler(res);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: DeleteNodeCommand,
        httpCode: HttpStatus.NO_CONTENT,
    })
    async deleteNode(@Param() param: DeleteNodeParamDto) {
        const res = await this.nodesService.deleteNode(param.uuid);
        errorHandler(res);
        return;
    }

    @Endpoint({
        type: NodeResponseDto,
        command: UpdateNodeCommand,
        httpCode: HttpStatus.OK,
    })
    async updateNode(@Body() body: UpdateNodeBodyDto): Promise<NodeResponseDto> {
        const res = await this.nodesService.updateNode(body);
        const data = errorHandler(res);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: RestartNodeCommand,
        httpCode: HttpStatus.ACCEPTED,
    })
    async restartNode(@Param() param: RestartNodeParamDto, @Body() body: RestartNodeBodyDto) {
        const res = await this.nodesService.restartNode(param.uuid, body.forceRestart);
        errorHandler(res);
        return;
    }

    @Endpoint({
        command: ResetNodeTrafficCommand,
        httpCode: HttpStatus.NO_CONTENT,
    })
    async resetNodeTraffic(@Param() param: ResetNodeTrafficParamDto) {
        const res = await this.nodesService.resetNodeTraffic(param.uuid);
        errorHandler(res);
        return;
    }

    @Endpoint({
        command: RestartAllNodesCommand,
        httpCode: HttpStatus.ACCEPTED,
    })
    async restartAllNodes(@Body() body: RestartAllNodesBodyDto) {
        const res = await this.nodesService.restartAllNodes(body.forceRestart);
        errorHandler(res);
        return;
    }

    @Endpoint({
        type: ReorderNodesResponseDto,
        command: ReorderNodesCommand,
        httpCode: HttpStatus.OK,
    })
    async reorderNodes(@Body() body: ReorderNodesBodyDto): Promise<ReorderNodesResponseDto> {
        const result = await this.nodesService.reorderNodes(body);

        const data = errorHandler(result);
        return {
            response: data,
        };
    }

    @Endpoint({
        command: BulkNodesProfileModificationCommand,
        httpCode: HttpStatus.NO_CONTENT,
    })
    async profileModification(@Body() body: ProfileModificationBodyDto) {
        const result = await this.nodesService.profileModification(body);

        errorHandler(result);
        return;
    }

    @Endpoint({
        command: BulkNodesActionsCommand,
        httpCode: HttpStatus.NO_CONTENT,
    })
    async bulkNodesActions(@Body() body: BulkNodesActionsBodyDto) {
        const result = await this.nodesService.bulkNodesActions(body);

        errorHandler(result);
        return;
    }

    @Endpoint({ command: BulkNodesUpdateCommand, httpCode: HttpStatus.NO_CONTENT })
    async bulkNodesUpdate(@Body() body: BulkNodesUpdateBodyDto) {
        const result = await this.nodesService.bulkNodesUpdate(body);
        errorHandler(result);
        return;
    }
}
