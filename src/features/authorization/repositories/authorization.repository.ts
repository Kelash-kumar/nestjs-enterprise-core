import { escapeLike } from '../../../common/persistence/escape-like';
import type { EntityManager } from 'typeorm';
import { ILike, In } from 'typeorm';
import { BadRequestException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import type { Authority } from '../interfaces/authority';
import { recoveryPermissions } from '../interfaces/authority';
import { RoleEntity } from '../entities/role.entity';
import { PermissionEntity } from '../entities/permission.entity';
import { UserRoleEntity } from '../entities/user-role.entity';
import { RolePermissionEntity } from '../entities/role-permission.entity';
import { UserPermissionEntity } from '../entities/user-permission.entity';
import { RoleInheritanceEntity } from '../entities/role-inheritance.entity';
import { UserEntity } from '../../users/entities/user.entity';
import { RolesRepository } from './roles.repository';
import { PermissionsRepository } from './permissions.repository';
import type { Principal } from '../../auth/interfaces/auth.types';
import { RecoveryRepository } from '../../auth/repositories/recovery.repository';
import type { PageQueryDto } from '../../../common/pagination/page-query.dto';
import { createPage, pageOffset, resolveSort } from '../../../common/pagination/page';

const effective = `effective_roles(id) AS (
  SELECT id FROM roots UNION SELECT edge.inherited_role_id FROM role_inheritance edge JOIN effective_roles parent ON edge.role_id=parent.id
), effective_permissions(id) AS (
  SELECT rp.permission_id FROM role_permissions rp JOIN effective_roles role ON rp.role_id=role.id
  UNION SELECT up.permission_id FROM user_permissions up JOIN subjects subject ON up.user_id=subject.id
)`;
const snapshot = `SELECT
  COALESCE((SELECT array_agg(id ORDER BY id) FROM effective_roles), ARRAY[]::uuid[]) AS "roleIds",
  COALESCE((SELECT array_agg(name ORDER BY name) FROM roles WHERE id IN (SELECT id FROM effective_roles)), ARRAY[]::varchar[]) AS roles,
  COALESCE((SELECT array_agg(name ORDER BY name) FROM permissions WHERE id IN (SELECT id FROM effective_permissions)), ARRAY[]::varchar[]) AS permissions`;

function readAuthority(value: unknown): Authority {
  if (!Array.isArray(value)) throw new Error('Invalid authority result');
  const row: unknown = value[0];
  const strings = (input: unknown): input is string[] =>
    Array.isArray(input) && input.every((item) => typeof item === 'string');
  if (
    !row ||
    typeof row !== 'object' ||
    !('roleIds' in row) ||
    !strings(row.roleIds) ||
    !('roles' in row) ||
    !strings(row.roles) ||
    !('permissions' in row) ||
    !strings(row.permissions)
  )
    throw new Error('Invalid authority result');
  return { roleIds: row.roleIds, roles: row.roles, permissions: row.permissions };
}

export class AuthorizationRepository {
  constructor(private readonly manager: EntityManager) {}
  recovery(): RecoveryRepository {
    return new RecoveryRepository(this.manager);
  }
  async setManagedStatus(id: string, status: 'active' | 'inactive'): Promise<void> {
    // Status authority is distinct from users.unlock; preserve password-failure/lock state.
    await this.manager
      .getRepository(UserEntity)
      .update(
        { id },
        { status, deactivationSource: status === 'inactive' ? 'administrative' : null },
      );
  }
  async lockPolicy(): Promise<void> {
    await this.manager.query('SELECT pg_advisory_xact_lock(23002, 1)');
  }
  async lockUsers(ids: string[]): Promise<void> {
    await this.manager
      .getRepository(UserEntity)
      .createQueryBuilder('user')
      .where({ id: In([...new Set(ids)].sort()) })
      .orderBy('user.id', 'ASC')
      .setLock('pessimistic_write')
      .getMany();
  }
  async requireActor(principal: Principal): Promise<void> {
    if (
      !(await new RecoveryRepository(this.manager).principal(
        principal.userId,
        principal.sessionId,
        new Date(),
      ))
    )
      throw new UnauthorizedException('Authentication required');
  }
  async userAuthority(userId: string): Promise<Authority> {
    const result: unknown = await this.manager.query(
      `WITH RECURSIVE subjects(id) AS (SELECT $1::uuid), roots(id) AS (SELECT role_id FROM user_roles WHERE user_id=$1), ${effective} ${snapshot}`,
      [userId],
    );
    return readAuthority(result);
  }
  async roleAuthority(roleId: string): Promise<Authority> {
    const result: unknown = await this.manager.query(
      `WITH RECURSIVE subjects(id) AS (SELECT NULL::uuid WHERE false), roots(id) AS (SELECT $1::uuid), ${effective} ${snapshot}`,
      [roleId],
    );
    return readAuthority(result);
  }
  async roleImpact(roleId: string): Promise<Authority> {
    const result: unknown = await this.manager.query(
      `WITH RECURSIVE affected(id) AS (
      SELECT $1::uuid UNION SELECT edge.role_id FROM role_inheritance edge JOIN affected role ON edge.inherited_role_id=role.id
    ), subjects(id) AS (SELECT DISTINCT user_id FROM user_roles WHERE role_id IN (SELECT id FROM affected)),
    roots(id) AS (SELECT id FROM affected UNION SELECT role_id FROM user_roles WHERE user_id IN (SELECT id FROM subjects)), ${effective} ${snapshot}`,
      [roleId],
    );
    return readAuthority(result);
  }
  async hasRecoveryManager(): Promise<boolean> {
    const rows: unknown = await this.manager.query(
      `WITH RECURSIVE subjects(id) AS (
      SELECT id FROM users WHERE deleted_at IS NULL AND status='active' AND (email_verified_at IS NOT NULL OR access_approved_at IS NOT NULL) AND (locked_until IS NULL OR locked_until <= CURRENT_TIMESTAMP)
    ), expanded(user_id, role_id) AS (
      SELECT ur.user_id, ur.role_id FROM user_roles ur JOIN subjects u ON ur.user_id=u.id
      UNION SELECT held.user_id, edge.inherited_role_id FROM expanded held JOIN role_inheritance edge ON held.role_id=edge.role_id
    ), granted(user_id, permission_id) AS (
      SELECT held.user_id, rp.permission_id FROM expanded held JOIN role_permissions rp ON held.role_id=rp.role_id
      UNION SELECT up.user_id, up.permission_id FROM user_permissions up JOIN subjects u ON up.user_id=u.id
    ) SELECT EXISTS (SELECT granted.user_id FROM granted JOIN permissions p ON p.id=granted.permission_id
      WHERE p.name = ANY($1::varchar[]) GROUP BY granted.user_id HAVING count(DISTINCT p.name)=$2) AS present`,
      [[...recoveryPermissions], recoveryPermissions.length],
    );
    if (!Array.isArray(rows)) throw new Error('Invalid recovery-manager result');
    const row: unknown = rows[0];
    return !!row && typeof row === 'object' && 'present' in row && row.present === true;
  }
  async role(id: string): Promise<RoleEntity> {
    const row = await this.manager.getRepository(RoleEntity).findOneBy({ id });
    if (!row) throw new NotFoundException('Role not found');
    return row;
  }
  async permission(id: string): Promise<PermissionEntity> {
    const row = await this.manager.getRepository(PermissionEntity).findOneBy({ id });
    if (!row) throw new NotFoundException('Permission not found');
    return row;
  }
  async user(id: string): Promise<UserEntity> {
    const row = await this.manager.getRepository(UserEntity).findOneBy({ id });
    if (!row) throw new NotFoundException('User not found');
    return row;
  }

  async directUserGrants(userId: string) {
    const [roles, permissions] = await Promise.all([
      this.manager.getRepository(UserRoleEntity).findBy({ userId }),
      this.manager.getRepository(UserPermissionEntity).findBy({ userId }),
    ]);
    return {
      directRoleIds: roles.map((row) => row.roleId).sort(),
      directPermissionIds: permissions.map((row) => row.permissionId).sort(),
    };
  }
  roles(query: PageQueryDto) {
    return new RolesRepository(this.manager).paginate(
      query,
      ['id', 'name', 'createdAt'],
      'name',
      query.search ? { name: ILike(`%${escapeLike(query.search)}%`) } : {},
    );
  }
  permissions(query: PageQueryDto) {
    return new PermissionsRepository(this.manager).paginate(
      query,
      ['id', 'name', 'createdAt'],
      'name',
      query.search ? { name: ILike(`%${escapeLike(query.search)}%`) } : {},
    );
  }
  createRole(name: string, description?: string) {
    return new RolesRepository(this.manager).create({ name, description });
  }
  updateRole(id: string, description: string) {
    return new RolesRepository(this.manager).update(id, { description });
  }
  deleteRole(id: string) {
    return new RolesRepository(this.manager).delete(id);
  }
  createPermission(resource: string, action: string) {
    return new PermissionsRepository(this.manager).create({ resource, action });
  }
  async membership(userId: string, roleId: string, grant: boolean): Promise<void> {
    if (grant) {
      const user = await this.user(userId),
        role = await this.role(roleId);
      if (role.guard !== (user.userType === 'admin' ? 'admin' : 'user'))
        throw new BadRequestException('Role guard must match account type');
    }
    const repository = this.manager.getRepository(UserRoleEntity);
    if (grant)
      await repository
        .createQueryBuilder()
        .insert()
        .values({ userId, roleId })
        .orIgnore()
        .execute();
    else await repository.delete({ userId, roleId });
  }
  async directPermission(userId: string, permissionId: string, grant: boolean): Promise<void> {
    const repository = this.manager.getRepository(UserPermissionEntity);
    if (grant)
      await repository
        .createQueryBuilder()
        .insert()
        .values({ userId, permissionId })
        .orIgnore()
        .execute();
    else await repository.delete({ userId, permissionId });
  }
  async rolePermission(roleId: string, permissionId: string, grant: boolean): Promise<void> {
    const repository = this.manager.getRepository(RolePermissionEntity);
    if (grant)
      await repository
        .createQueryBuilder()
        .insert()
        .values({ roleId, permissionId })
        .orIgnore()
        .execute();
    else await repository.delete({ roleId, permissionId });
  }
  async inheritance(roleId: string, inheritedRoleId: string, grant: boolean): Promise<void> {
    if (grant && (await this.role(roleId)).guard !== (await this.role(inheritedRoleId)).guard)
      throw new BadRequestException('Inherited roles must use the same guard');
    const repository = this.manager.getRepository(RoleInheritanceEntity);
    if (grant)
      await repository
        .createQueryBuilder()
        .insert()
        .values({ roleId, inheritedRoleId })
        .orIgnore()
        .execute();
    else await repository.delete({ roleId, inheritedRoleId });
  }
  async details(id: string) {
    const role = await this.role(id);
    const [authority, permissions, inheritance] = await Promise.all([
      this.roleAuthority(id),
      this.manager.getRepository(RolePermissionEntity).findBy({ roleId: id }),
      this.manager.getRepository(RoleInheritanceEntity).findBy({ roleId: id }),
    ]);
    return {
      id: role.id,
      name: role.name,
      description: role.description,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
      permissionIds: permissions.map((row) => row.permissionId).sort(),
      inheritedRoleIds: inheritance.map((row) => row.inheritedRoleId).sort(),
      ...authority,
    };
  }
  async users(query: PageQueryDto) {
    const sort = resolveSort(query.sortBy, ['id', 'email', 'createdAt', 'status'], 'createdAt');
    const builder = this.manager
      .getRepository(UserEntity)
      .createQueryBuilder('user')
      .select([
        'user.id',
        'user.email',
        'user.userType',
        'user.status',
        'user.deactivationSource',
        'user.emailVerifiedAt',
        'user.lockedUntil',
        'user.createdAt',
      ])
      .orderBy(`user.${sort}`, query.sortOrder === 'asc' ? 'ASC' : 'DESC');
    if (sort !== 'id') builder.addOrderBy('user.id', 'ASC');
    if (query.search)
      builder.andWhere('user.email ILIKE :search', { search: `%${escapeLike(query.search)}%` });
    const [rows, total] = await builder.skip(pageOffset(query)).take(query.limit).getManyAndCount();
    return createPage(
      rows.map((row) => ({
        id: row.id,
        email: row.email,
        userType: row.userType,
        status: row.status,
        deactivationSource: row.deactivationSource,
        emailVerifiedAt: row.emailVerifiedAt,
        lockedUntil: row.lockedUntil,
        createdAt: row.createdAt,
      })),
      total,
      query,
    );
  }
}
