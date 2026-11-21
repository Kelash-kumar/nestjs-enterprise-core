import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { Response } from 'express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCookieAuth,
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { RawResponse } from '../../../common/http/response.decorator';
import { Authenticated } from '../../authorization/decorators/access.decorators';
import { ApiSuccess } from '../../../common/http/api-success.decorator';
import { PageQueryDto } from '../../../common/pagination/page-query.dto';
import { CurrentUser, Public } from '../decorators/auth.decorators';
import {
  RegisterDto,
  LoginDto,
  VerificationDto,
  EmailDto,
  CredentialsDto,
  MessageDto,
  PrincipalDto,
  CsrfDto,
  SessionPageDto,
  LoginCodeDto,
  LoginChallengeDto,
} from '../dto/auth.dto';
import type { AuthRequest, Principal } from '../interfaces/auth.types';
import { RegistrationService } from '../services/registration.service';
import { SessionAuthService } from '../services/session-auth.service';
import { SessionCookies } from '../transport/session-cookies';
import { AuthOriginGuard } from '../guards/origin.guard';
import { CsrfGuard } from '../guards/csrf.guard';
import { LocalAuthenticationGuard } from '../guards/local-authentication.guard';

const genericRegistration = {
  message: 'If this address can be registered, verification instructions are queued.',
};

@ApiTags('authentication')
@Controller({ path: 'auth', version: '1' })
@Authenticated()
@UseGuards(AuthOriginGuard)
@ApiHeader({
  name: 'Origin',
  required: false,
  description:
    'Exact configured origin; required for every auth mutation, including login and CSRF bootstrap.',
})
export class AuthController {
  constructor(
    private readonly registration: RegistrationService,
    private readonly sessions: SessionAuthService,
    private readonly cookies: SessionCookies,
  ) {}

  @Post('register')
  @Public()
  @HttpCode(202)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  @ApiSuccess(MessageDto, 202)
  async register(@Body() input: RegisterDto) {
    await this.registration.register(input.email, input.password);
    return genericRegistration;
  }

  @Post('verification/request')
  @Public()
  @HttpCode(202)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  @ApiSuccess(MessageDto, 202)
  async resend(@Body() input: EmailDto) {
    await this.registration.requestVerification(input.email);
    return genericRegistration;
  }

  @Post('verify-email')
  @Public()
  @HttpCode(204)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  verify(@Body() input: VerificationDto) {
    return this.registration.verify(input.token);
  }

  @Post('login')
  @Public()
  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiSuccess([CredentialsDto, LoginChallengeDto])
  @ApiBody({ type: LoginDto })
  login(
    @Body() input: LoginDto,
    @Req() request: AuthRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.startLogin(input, request, response, false);
  }

  @Post('admin/login')
  @Public()
  @HttpCode(200)
  @UseGuards(LocalAuthenticationGuard)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiSuccess([CredentialsDto, LoginChallengeDto])
  @ApiBody({ type: LoginDto })
  @ApiOperation({ summary: 'Login to the admin portal; requires current admin.access permission' })
  adminLogin(
    @Body() input: LoginDto,
    @Req() request: AuthRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.startLogin(input, request, response, true);
  }

  private async startLogin(
    input: LoginDto,
    request: AuthRequest,
    response: Response,
    adminPortal: boolean,
  ) {
    if (!request.loginIdentity) throw new UnauthorizedException('Authentication required');
    const result = await this.sessions.login(
      request.loginIdentity,
      {
        name: input.deviceName,
        userAgent: request.headers['user-agent'],
        ip: request.ip,
      },
      adminPortal,
    );
    return 'mfaRequired' in result ? result : this.cookies.write(response, result);
  }

  @Post('login/verify')
  @Public()
  @HttpCode(200)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @ApiSuccess(CredentialsDto)
  async verifyLogin(
    @Body() input: LoginCodeDto,
    @Req() request: AuthRequest,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.sessions.verifyLogin(input.challengeToken, input.code, {
      name: 'Verified web login',
      userAgent: request.headers['user-agent'],
      ip: request.ip,
    });
    if ('mfaRequired' in result) throw new UnauthorizedException('Verification required');
    return this.cookies.write(response, result);
  }

  @Post('csrf')
  @ApiCookieAuth('refresh-cookie')
  @Public()
  @HttpCode(200)
  @ApiSuccess(CsrfDto)
  @ApiOperation({
    summary: 'Recover session-bound CSRF token using refresh cookie and permitted Origin',
  })
  csrf(@Req() request: AuthRequest) {
    return { csrfToken: this.cookies.csrf(this.cookies.read(request)) };
  }

  @Post('refresh')
  @ApiCookieAuth('refresh-cookie')
  @Public()
  @HttpCode(200)
  @UseGuards(CsrfGuard)
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  @ApiHeader({ name: 'X-CSRF-Token', required: true })
  @ApiSuccess(CredentialsDto)
  async refresh(@Req() request: AuthRequest, @Res({ passthrough: true }) response: Response) {
    try {
      return this.cookies.write(response, await this.sessions.refresh(this.cookies.read(request)));
    } catch (error) {
      if (error instanceof UnauthorizedException) this.cookies.clear(response);
      throw error;
    }
  }

  @Post('logout')
  @ApiCookieAuth('refresh-cookie')
  @Public()
  @HttpCode(204)
  @UseGuards(CsrfGuard)
  @ApiHeader({ name: 'X-CSRF-Token', required: true })
  async logout(@Req() request: AuthRequest, @Res({ passthrough: true }) response: Response) {
    await this.sessions.logout(this.cookies.read(request));
    this.cookies.clear(response);
  }

  @Post('logout-all')
  @ApiBearerAuth()
  @HttpCode(204)
  async logoutAll(
    @CurrentUser() principal: Principal,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.sessions.revoke(principal);
    this.cookies.clear(response);
  }

  @Get('me')
  @ApiBearerAuth()
  @ApiSuccess(PrincipalDto)
  me(@CurrentUser() principal: Principal) {
    return principal;
  }

  @Get('sessions')
  @ApiBearerAuth()
  @RawResponse()
  @ApiResponse({ status: 200, type: SessionPageDto })
  list(@CurrentUser() principal: Principal, @Query() query: PageQueryDto) {
    return this.sessions.list(principal, query);
  }

  @Delete('sessions/:id')
  @ApiBearerAuth()
  @HttpCode(204)
  revoke(@CurrentUser() principal: Principal, @Param('id', new ParseUUIDPipe()) id: string) {
    return this.sessions.revoke(principal, id);
  }
}
