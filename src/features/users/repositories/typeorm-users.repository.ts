import { escapeLike } from '../../../common/persistence/escape-like';
import { ILike } from 'typeorm';
import type { EntityManager, FindOptionsWhere } from 'typeorm';
import { ManagementRepository } from '../../../common/persistence/management.repository';
import type { PageQueryDto } from '../../../common/pagination/page-query.dto';
import { UserEntity } from '../entities/user.entity';
import type {
  NewUser,
  UserFilters,
  UsersRepository,
} from '../interfaces/users-repository.interface';

export class TypeormUsersRepository
  extends ManagementRepository<UserEntity>
  implements UsersRepository
{
  constructor(manager: EntityManager) {
    super(UserEntity, manager);
  }

  async createUser(input: NewUser): Promise<UserEntity> {
    return this.create({ ...input, email: input.email.trim().toLowerCase() });
  }

  findByEmail(email: string): Promise<UserEntity | null> {
    return this.findOne({ email: email.trim().toLowerCase() });
  }

  /** Explicit opt-in for the future password verifier, never for HTTP response serialization. */
  findCredentials(email: string): Promise<UserEntity | null> {
    return this.execute(() =>
      this.repository
        .createQueryBuilder('user')
        .addSelect('user.passwordHash')
        .where('user.email = :email', { email: email.trim().toLowerCase() })
        .getOne(),
    );
  }

  list(query: PageQueryDto, filters: UserFilters = {}) {
    const where: FindOptionsWhere<UserEntity> = { ...filters };
    if (query.search) {
      // Search treats SQL LIKE metacharacters literally; parameters still handle SQL injection prevention.
      const literal = escapeLike(query.search);
      where.email = ILike(`%${literal}%`);
    }
    return this.paginate(query, ['id', 'email', 'createdAt', 'updatedAt'], 'createdAt', where);
  }
}
