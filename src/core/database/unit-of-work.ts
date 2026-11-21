import { Injectable } from '@nestjs/common';
import { DataSource } from 'typeorm';
import type { EntityManager } from 'typeorm';
import { mapDatabaseError } from '../../common/errors/database-error';

export class TransactionScope {
  private active = true;
  constructor(private readonly transactionManager: EntityManager) {}
  get manager(): EntityManager {
    if (!this.active) throw new Error('Transaction scope is closed');
    return this.transactionManager;
  }
  get<T>(repository: new (manager: EntityManager) => T): T {
    return new repository(this.manager);
  }
  close(): void {
    this.active = false;
  }
}

@Injectable()
export class UnitOfWork {
  constructor(private readonly source: DataSource) {}

  async run<T>(work: (scope: TransactionScope) => Promise<T>): Promise<T> {
    try {
      return await this.source.transaction('READ COMMITTED', async (manager) => {
        const scope = new TransactionScope(manager);
        try {
          return await work(scope);
        } finally {
          scope.close();
        }
      });
    } catch (error) {
      throw mapDatabaseError(error);
    }
  }
}
