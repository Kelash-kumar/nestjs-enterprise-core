import { NotFoundException } from '@nestjs/common';
import { UserEntity } from '../users/entities/user.entity';
import { CompanyEntity } from '../companies/entities/company.entity';
import { RoleEntity } from '../authorization/entities/role.entity';
import { PermissionEntity } from '../authorization/entities/permission.entity';

const accounts = {
  entity: UserEntity,
  search: ['email', 'firstName', 'lastName', 'username', 'phone'],
  sort: [
    'email',
    'firstName',
    'lastName',
    'phone',
    'notificationChannel',
    'twoFactor',
    'createdAt',
    'status',
  ],
  export: [
    'id',
    'fullName',
    'username',
    'email',
    'phone',
    'companyId',
    'notificationChannel',
    'twoFactor',
    'createdAt',
    'deletedAt',
  ],
};
export const crmModules = {
  users: accounts,
  admins: accounts,
  companies: {
    entity: CompanyEntity,
    search: ['name', 'email', 'phone'],
    sort: ['name', 'email', 'phone', 'createdAt'],
    export: ['id', 'name', 'email', 'phone', 'website', 'address', 'createdAt', 'deletedAt'],
  },
  roles: {
    entity: RoleEntity,
    search: ['name'],
    sort: ['name', 'createdAt'],
    export: ['id', 'name', 'guard', 'description', 'createdAt'],
  },
  permissions: {
    entity: PermissionEntity,
    search: ['name'],
    sort: ['name', 'createdAt'],
    export: ['id', 'name', 'resource', 'action', 'createdAt'],
  },
};
export type CrmKind = keyof typeof crmModules;

export function crmKind(value: string): CrmKind {
  if (!Object.hasOwn(crmModules, value)) throw new NotFoundException('Module not found');
  return value as CrmKind;
}
