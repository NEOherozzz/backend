import { ApiTokenEntity } from '../entities/api-token.entity';

export class FindAllApiTokensResponseModel {
    public tokens: {
        uuid: string;
        name: string;
        expireAt: Date;
        scopes: string[];

        createdAt: Date;
        updatedAt: Date;
    }[];

    public docs: {
        enabled: boolean;
        scalarPath: null | string;
        swaggerPath: null | string;
    };

    constructor(
        data: ApiTokenEntity,
        docs: { enabled: boolean; scalarPath: null | string; swaggerPath: null | string },
    ) {
        this.tokens = [
            {
                uuid: data.uuid,
                name: data.name,
                expireAt: data.expireAt,
                scopes: data.scopes,
                createdAt: data.createdAt,
                updatedAt: data.updatedAt,
            },
        ];
        this.docs = {
            enabled: docs.enabled,
            scalarPath: docs.scalarPath,
            swaggerPath: docs.swaggerPath,
        };
    }
}
