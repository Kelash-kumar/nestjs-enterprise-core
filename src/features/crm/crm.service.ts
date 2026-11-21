import { escapeLike } from '../../common/persistence/escape-like';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { DataSource, In, Not } from 'typeorm';
import type { EntityManager } from 'typeorm';
import { AuthorizationService } from '../authorization/services/authorization.service';
import { AuthorizationRepository } from '../authorization/repositories/authorization.repository';
import { assertGrantScope, assertPermissionScope } from '../authorization/policies/grant.policy';
import type { Authority } from '../authorization/interfaces/authority';
import { UserEntity } from '../users/entities/user.entity';
import { CompanyEntity } from '../companies/entities/company.entity';
import { RoleEntity } from '../authorization/entities/role.entity';
import { PermissionEntity } from '../authorization/entities/permission.entity';
import { RolePermissionEntity } from '../authorization/entities/role-permission.entity';
import { UserRoleEntity } from '../authorization/entities/user-role.entity';
import { UserPermissionEntity } from '../authorization/entities/user-permission.entity';
import { RoleInheritanceEntity } from '../authorization/entities/role-inheritance.entity';
import { RegistrationService } from '../auth/services/registration.service';
import { PASSWORD_HASHER } from '../auth/interfaces/auth.types';
import type { PasswordHasher, Principal } from '../auth/interfaces/auth.types';
import { createPage, pageOffset, resolveSort } from '../../common/pagination/page';
import type {
  CrmQueryDto,
  CreateCrmUserDto,
  UpdateCrmUserDto,
  CrmRoleDto,
  CrmBulkDto,
} from './crm.dto';
import type { CreateCompanyDto, UpdateCompanyDto } from '../companies/dto/company.dto';
import { CompaniesRepository } from '../companies/repositories/companies.repository';

import { crmModules, type CrmKind } from './crm-modules';

const profileKeys = [
  'firstName',
  'lastName',
  'phone',
  'companyId',
  'username',
  'dateOfBirth',
  'gender',
  'avatarData',
  'notificationChannel',
  'twoFactor',
] as const;
function profile(input: CreateCrmUserDto | UpdateCrmUserDto) {
  const result = Object.fromEntries(
    profileKeys.filter((key) => input[key] !== undefined).map((key) => [key, input[key]]),
  );
  if (typeof result.username === 'string') result.username = result.username.toLowerCase();
  if (input.dateOfBirth && input.dateOfBirth >= new Date().toISOString().slice(0, 10))
    throw new BadRequestException('Date of birth must be before today');
  if (input.avatarData) {
    const match = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(
      input.avatarData,
    );
    if (!match) throw new BadRequestException('Use a PNG, JPEG or WebP avatar');
    const bytes = Buffer.from(match[2]!, 'base64');
    const valid =
      match[1] === 'png'
        ? bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
        : match[1] === 'jpeg'
          ? bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255
          : bytes.subarray(0, 4).toString() === 'RIFF' &&
            bytes.subarray(8, 12).toString() === 'WEBP';
    if (!valid || bytes.length > 6000)
      throw new BadRequestException('Avatar must be a valid image under 6KB');
  }
  return result;
}
function userView(row: UserEntity) {
  return {
    id: row.id,
    email: row.email,
    userType: row.userType,
    firstName: row.firstName,
    lastName: row.lastName,
    fullName: [row.firstName, row.lastName].filter(Boolean).join(' ') || row.email,
    phone: row.phone,
    companyId: row.companyId,
    username: row.username,
    dateOfBirth: row.dateOfBirth,
    gender: row.gender,
    avatarData: row.avatarData,
    notificationChannel: row.notificationChannel,
    twoFactor: row.twoFactor,
    status: row.status,
    emailVerifiedAt: row.emailVerifiedAt,
    accessApprovedAt: row.accessApprovedAt,
    deletedAt: row.deletedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}
@Injectable()
export class CrmService {
  constructor(
    private readonly source: DataSource,
    private readonly authorization: AuthorizationService,
    private readonly registration: RegistrationService,
    @Inject(PASSWORD_HASHER) private readonly passwords: PasswordHasher,
  ) {}
  async require(principal: Principal, required: string[]) {
    const actor = await this.authorization.authority(principal.userId);
    if (required.some((permission) => !actor.permissions.includes(permission)))
      throw new ForbiddenException('Insufficient permission');
    return actor;
  }
  async list(principal: Principal, kind: CrmKind, query: CrmQueryDto) {
    await this.require(principal, [kind + '.read']);
    if (query.fromDate && query.toDate && new Date(query.fromDate) > new Date(query.toDate))
      throw new BadRequestException('Invalid date range');
    const { entity, search, sort: sortable } = crmModules[kind];
    const account = entity === UserEntity;
    const builder = this.source.manager.createQueryBuilder(entity, 'record');
    if (account)
      builder.andWhere('record.userType ' + (kind === 'admins' ? '=' : '<>') + ' :type', {
        type: 'admin',
      });
    if (account || kind === 'companies') {
      if (query.deleted !== 'active') builder.withDeleted();
      if (query.deleted === 'only') builder.andWhere('record.deletedAt IS NOT NULL');
    } else if (query.deleted !== 'active')
      throw new BadRequestException('Deleted filtering is unavailable for this module');
    if (query.companyId && account)
      builder.andWhere('record.companyId=:company', { company: query.companyId });
    if (query.guard && kind === 'roles')
      builder.andWhere('record.guard=:guard', { guard: query.guard });
    if (query.fromDate) builder.andWhere('record.createdAt >= :from', { from: query.fromDate });
    if (query.toDate)
      builder.andWhere('record.createdAt < :to', {
        to: new Date(new Date(query.toDate.slice(0, 10) + 'T00:00:00.000Z').getTime() + 86400000),
      });
    if (query.search?.trim())
      builder.andWhere(
        '(' + search.map((key) => 'record.' + key + ' ILIKE :search').join(' OR ') + ')',
        { search: '%' + escapeLike(query.search) + '%' },
      );
    const sort = resolveSort(query.sortBy, sortable, 'createdAt');
    const [data, total] = await builder
      .orderBy('record.' + sort, query.sortOrder === 'asc' ? 'ASC' : 'DESC')
      .addOrderBy('record.id', 'ASC')
      .skip(pageOffset(query))
      .take(query.limit)
      .getManyAndCount();
    return createPage(
      data.map((row) => (row instanceof UserEntity ? userView(row) : row)),
      total,
      query,
    );
  }
  async find(principal: Principal, kind: CrmKind, id: string) {
    await this.require(principal, [kind + '.read']);
    if (kind === 'roles')
      return new AuthorizationRepository(this.source.manager).details(id).then(async (details) => ({
        ...details,
        guard: (await this.source.getRepository(RoleEntity).findOneByOrFail({ id })).guard,
      }));
    if (kind === 'companies') {
      const row = await this.source
        .getRepository(CompanyEntity)
        .findOne({ where: { id }, withDeleted: true });
      if (!row) throw new NotFoundException('Company not found');
      return row;
    }
    if (kind === 'permissions') {
      const row = await this.source.getRepository(PermissionEntity).findOneBy({ id });
      if (!row) throw new NotFoundException('Permission not found');
      return row;
    }
    const row = await this.source.getRepository(UserEntity).findOne({
      where: { id, userType: kind === 'admins' ? 'admin' : Not('admin') },
      withDeleted: true,
    });
    if (!row) throw new NotFoundException('Account not found');
    const grants = await new AuthorizationRepository(this.source.manager).directUserGrants(id);
    return {
      ...userView(row),
      roleIds: grants.directRoleIds,
      permissionIds: grants.directPermissionIds,
    };
  }
  private async assignablePermissions(
    manager: EntityManager,
    actor: Authority,
    ids: string[],
    message: string,
  ) {
    if (
      !actor.permissions.includes('permissions.assign') ||
      !actor.permissions.includes('permissions.revoke')
    )
      throw new ForbiddenException(message);
    const permissions = await manager.getRepository(PermissionEntity).findBy({ id: In(ids) });
    if (permissions.length !== new Set(ids).size)
      throw new BadRequestException('Permission not found');
    for (const permission of permissions) assertPermissionScope(actor, permission.name);
    return permissions;
  }
  private async grants(
    manager: EntityManager,
    policy: AuthorizationRepository,
    actor: Authority,
    id: string,
    input: { roleIds?: string[]; permissionIds?: string[] },
    guard: 'admin' | 'user',
  ) {
    if (input.roleIds !== undefined) {
      if (!actor.permissions.includes('roles.assign'))
        throw new ForbiddenException('Role assignment is not permitted');
      const roles = await manager.getRepository(RoleEntity).findBy({ id: In(input.roleIds) });
      if (roles.length !== new Set(input.roleIds).size)
        throw new BadRequestException('Role not found');
      for (const role of roles) {
        if (role.guard !== guard)
          throw new BadRequestException('Role guard must match account type');
        assertGrantScope(actor, await policy.roleAuthority(role.id));
      }
      await manager.getRepository(UserRoleEntity).delete({ userId: id });
      for (const role of roles) await policy.membership(id, role.id, true);
    }
    if (input.permissionIds !== undefined) {
      const permissions = await this.assignablePermissions(
        manager,
        actor,
        input.permissionIds,
        'Direct permission management is not permitted',
      );
      await manager.getRepository(UserPermissionEntity).delete({ userId: id });
      for (const permission of permissions) await policy.directPermission(id, permission.id, true);
    }
  }
  async saveUser(
    principal: Principal,
    kind: 'admins' | 'users',
    input: CreateCrmUserDto | UpdateCrmUserDto,
    id?: string,
  ) {
    const changes = profile(input);
    let hash: string | undefined;
    if (!id) {
      const create = input as CreateCrmUserDto;
      if (create.password !== create.confirmPassword || create.password.length < 15)
        throw new BadRequestException('Passwords must match and contain at least 15 characters');
      hash = await this.passwords.hash(create.password);
    }
    return this.authorization.mutate(
      principal,
      [kind + (id ? '.update' : '.create')],
      id ? [id] : [],
      async (policy, actor, scope) => {
        const manager = scope.manager;
        if (input.companyId) await scope.get(CompaniesRepository).require(input.companyId);
        if (id) {
          const row = await manager
            .getRepository(UserEntity)
            .findOneBy({ id, userType: kind === 'admins' ? 'admin' : Not('admin') });
          if (!row) throw new NotFoundException('Account not found');
          assertGrantScope(actor, await policy.userAuthority(id));
          if ('allowLogin' in input && input.allowLogin === true) {
            if (row.status !== 'active')
              throw new BadRequestException(
                'Restore or activate this account before enabling login',
              );
            await policy.recovery().approveManagedAccess(id, principal.userId, new Date());
          }
        } else {
          id =
            (await this.registration.provisionManaged(
              policy.recovery(),
              (input as CreateCrmUserDto).email,
              hash!,
              principal.userId,
            )) ?? undefined;
          if (!id) throw new ConflictException('Resource already exists');
        }
        await manager.getRepository(UserEntity).update(id, {
          ...changes,
          ...(!('email' in input) ? {} : { userType: kind === 'admins' ? 'admin' : 'customer' }),
        });
        await this.grants(manager, policy, actor, id, input, kind === 'admins' ? 'admin' : 'user');
        return userView(await manager.getRepository(UserEntity).findOneByOrFail({ id }));
      },
    );
  }
  saveRole(principal: Principal, input: CrmRoleDto, id?: string) {
    return this.authorization.mutate(
      principal,
      id ? ['roles.update'] : ['roles.create', 'roles.delegate'],
      [],
      async (policy, actor, scope) => {
        const manager = scope.manager;
        const role = id ? await policy.role(id) : manager.getRepository(RoleEntity).create();
        if (id) {
          assertGrantScope(actor, await policy.roleImpact(id));
          if (
            role.guard !== input.guard &&
            ((await manager.getRepository(UserRoleEntity).existsBy({ roleId: id })) ||
              (await manager
                .getRepository(RoleInheritanceEntity)
                .exists({ where: [{ roleId: id }, { inheritedRoleId: id }] })))
          )
            throw new ConflictException('Unassign roles and inheritance before changing guard');
        }
        role.name = input.name;
        role.guard = input.guard;
        role.description = input.description ?? null;
        const saved = await manager.getRepository(RoleEntity).save(role);
        if (input.permissionIds !== undefined) {
          const permissions = await this.assignablePermissions(
            manager,
            actor,
            input.permissionIds,
            'Permission matrix management is not permitted',
          );
          await manager.getRepository(RolePermissionEntity).delete({ roleId: saved.id });
          for (const permission of permissions)
            await policy.rolePermission(saved.id, permission.id, true);
        }
        return saved;
      },
    );
  }
  saveCompany(principal: Principal, input: CreateCompanyDto | UpdateCompanyDto, id?: string) {
    return this.authorization.mutate(
      principal,
      ['companies.' + (id ? 'update' : 'create')],
      [],
      async (_policy, _actor, scope) => {
        const repository = scope.get(CompaniesRepository);
        if (!id) return repository.create(input);
        await repository.require(id);
        await repository.update(id, input);
        return repository.require(id);
      },
    );
  }
  bulk(principal: Principal, kind: CrmKind, input: CrmBulkDto) {
    if (kind === 'permissions' || (input.action === 'restore' && kind === 'roles'))
      throw new BadRequestException('Operation is unavailable');
    const ids = [...new Set(input.ids)];
    return this.authorization.mutate(
      principal,
      [kind + '.' + (input.action === 'delete' ? 'delete' : 'restore')],
      kind === 'users' || kind === 'admins' ? ids : [],
      async (policy, actor, scope) => {
        const manager = scope.manager;
        for (const id of ids) {
          if (kind === 'roles') {
            await policy.role(id);
            assertGrantScope(actor, await policy.roleImpact(id));
            await policy.deleteRole(id);
          } else if (kind === 'companies') {
            const row = await manager
              .getRepository(CompanyEntity)
              .findOne({ where: { id }, withDeleted: true });
            if (!row) throw new NotFoundException('Company not found');
            if (
              input.action === 'delete' &&
              (await manager
                .getRepository(UserEntity)
                .exists({ where: { companyId: id }, withDeleted: true }))
            )
              throw new ConflictException('Unlink all accounts before deleting the company');
            await manager
              .getRepository(CompanyEntity)
              .update(id, { deletedAt: input.action === 'delete' ? new Date() : null });
          } else {
            const row = await manager.getRepository(UserEntity).findOne({
              where: { id, userType: kind === 'admins' ? 'admin' : Not('admin') },
              withDeleted: true,
            });
            if (!row) throw new NotFoundException('Account not found');
            assertGrantScope(actor, await policy.userAuthority(id));
            if (input.action === 'restore' && !row.deletedAt)
              throw new ConflictException('Account is not deleted');
            const at = new Date();
            await policy.recovery().invalidateRecovery(id, at);
            await policy.recovery().revokeAll(id, at);
            await manager.getRepository(UserEntity).update(id, {
              deletedAt: input.action === 'delete' ? at : null,
              status: input.action === 'delete' ? 'inactive' : 'active',
              deactivationSource: input.action === 'delete' ? 'administrative' : null,
            });
          }
        }
        return { affected: ids.length };
      },
    );
  }
}
