import {
  Body,
  Controller,
  Get,
  Post,
  Patch,
  Param,
  ParseUUIDPipe,
  Query,
  Res,
  UseGuards,
  HttpCode,
  BadRequestException,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiExtraModels,
  getSchemaPath,
} from '@nestjs/swagger';
import { Authenticated } from '../authorization/decorators/access.decorators';
import { CurrentUser } from '../auth/decorators/auth.decorators';
import type { Principal } from '../auth/interfaces/auth.types';
import { AuthOriginGuard } from '../auth/guards/origin.guard';
import { RawResponse } from '../../common/http/response.decorator';
import { createValidationPipe } from '../../common/http/validation.pipe';
import { CrmService } from './crm.service';
import { crmKind, crmModules } from './crm-modules';
import { CrmQueryDto, CrmBulkDto, CrmRoleDto, CreateCrmUserDto, UpdateCrmUserDto } from './crm.dto';
import { CreateCompanyDto, UpdateCompanyDto } from '../companies/dto/company.dto';
import { exportRecords } from './crm-export';
@ApiTags('CRM management')
@ApiExtraModels(CreateCrmUserDto, UpdateCrmUserDto, CrmRoleDto, CreateCompanyDto, UpdateCompanyDto)
@ApiBearerAuth()
@Controller({ path: 'crm', version: '1' })
@Authenticated()
@UseGuards(AuthOriginGuard)
export class CrmController {
  constructor(private readonly service: CrmService) {}
  @Get(':module')
  @RawResponse()
  list(
    @CurrentUser() principal: Principal,
    @Param('module') module: string,
    @Query() query: CrmQueryDto,
  ) {
    return this.service.list(principal, crmKind(module), query);
  }
  @Get(':module/export')
  @ApiOperation({
    summary:
      'Export filtered records as CSV or real XLSX; requires module.read and module.export; maximum 5000 records',
  })
  async export(
    @CurrentUser() principal: Principal,
    @Param('module') module: string,
    @Query() query: CrmQueryDto,
    @Res() response: Response,
  ) {
    const kind = crmKind(module);
    await this.service.require(principal, [kind + '.read', kind + '.export']);
    const rows: Record<string, unknown>[] = [];
    for (let page = 1; page <= 50; page++) {
      const result = await this.service.list(
        principal,
        kind,
        Object.assign(new CrmQueryDto(), query, { page, limit: 100 }),
      );
      if (result.meta.total > 5000)
        throw new BadRequestException('Export is limited to 5000 records. Narrow the filters.');
      rows.push(...(result.data as unknown as Record<string, unknown>[]));
      if (!result.meta.hasNextPage) break;
    }
    const format = query.format ?? 'csv';
    response.setHeader('Cache-Control', 'no-store');
    response.type(
      format === 'csv'
        ? 'text/csv; charset=utf-8'
        : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    );
    response.attachment(kind + '.' + format);
    response.send(exportRecords(rows, crmModules[kind].export, format));
  }
  @Get(':module/:id')
  find(
    @CurrentUser() principal: Principal,
    @Param('module') module: string,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.service.find(principal, crmKind(module), id);
  }
  @Post(':module/bulk')
  @HttpCode(200)
  bulk(
    @CurrentUser() principal: Principal,
    @Param('module') module: string,
    @Body() input: CrmBulkDto,
  ) {
    return this.service.bulk(principal, crmKind(module), input);
  }
  @Post(':module')
  @ApiBody({
    schema: {
      oneOf: [CreateCrmUserDto, CrmRoleDto, CreateCompanyDto].map((model) => ({
        $ref: getSchemaPath(model),
      })),
    },
  })
  create(
    @CurrentUser() principal: Principal,
    @Param('module') module: string,
    @Body() body: unknown,
  ) {
    return this.save(principal, module, body);
  }
  @Patch(':module/:id')
  @ApiBody({
    schema: {
      oneOf: [UpdateCrmUserDto, CrmRoleDto, UpdateCompanyDto].map((model) => ({
        $ref: getSchemaPath(model),
      })),
    },
  })
  update(
    @CurrentUser() principal: Principal,
    @Param('module') module: string,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    return this.save(principal, module, body, id);
  }
  private async save(principal: Principal, module: string, body: unknown, id?: string) {
    const kind = crmKind(module),
      validation = createValidationPipe();
    if (kind === 'users' || kind === 'admins') {
      const input = (await validation.transform(body, {
        type: 'body',
        metatype: id ? UpdateCrmUserDto : CreateCrmUserDto,
      })) as CreateCrmUserDto | UpdateCrmUserDto;
      return this.service.saveUser(principal, kind, input, id);
    }
    if (kind === 'roles')
      return this.service.saveRole(
        principal,
        (await validation.transform(body, { type: 'body', metatype: CrmRoleDto })) as CrmRoleDto,
        id,
      );
    if (kind === 'companies')
      return this.service.saveCompany(
        principal,
        (await validation.transform(body, {
          type: 'body',
          metatype: id ? UpdateCompanyDto : CreateCompanyDto,
        })) as CreateCompanyDto | UpdateCompanyDto,
        id,
      );
    throw new BadRequestException(
      'Use the existing permission catalog endpoint to create definitions',
    );
  }
}
