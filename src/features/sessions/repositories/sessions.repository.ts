import type { EntityManager } from 'typeorm';
import { BaseRepository } from '../../../common/persistence/base.repository';
import { SessionEntity } from '../entities/session.entity';

export class SessionsRepository extends BaseRepository<SessionEntity> {
  constructor(manager: EntityManager) {
    super(SessionEntity, manager);
  }
}
