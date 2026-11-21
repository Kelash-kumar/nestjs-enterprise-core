import { escapeLike } from './escape-like';
import { NotFoundException } from '@nestjs/common';
import { ILike } from 'typeorm';
import type { FindOptionsWhere } from 'typeorm';
import { BaseRepository } from './base.repository';
import type { BaseEntity } from './base.entity';
import type { PageQueryDto } from '../pagination/page-query.dto';
export abstract class ManagementRepository<T extends BaseEntity> extends BaseRepository<T> {
  async require(id: string): Promise<T> {
    const row = await this.findById(id);
    if (!row) throw new NotFoundException('Resource not found');
    return row;
  }
  searchPage(
    query: PageQueryDto,
    searchable: readonly (keyof T & string)[],
    sortable: readonly (keyof T & string)[],
    filters: FindOptionsWhere<T> = {},
  ) {
    const literal = query.search && escapeLike(query.search);
    const where = literal
      ? searchable.map((field) => ({ ...filters, [field]: ILike('%' + literal + '%') }))
      : filters;
    return this.paginate(query, sortable, 'createdAt', where);
  }
}
