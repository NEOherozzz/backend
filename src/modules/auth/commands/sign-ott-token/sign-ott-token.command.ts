import { Command } from '@nestjs/cqrs';

import { TResult } from '@common/types';

export class SignOttTokenCommand extends Command<TResult<string>> {
    constructor() {
        super();
    }
}
