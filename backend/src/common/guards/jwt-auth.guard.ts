import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PUBLIC_KEY } from '../decorators/public.decorator';
import { Reflector } from '@nestjs/core';
import { AuthException } from '../exceptions';
import { ErrorCode } from '../constants/error-codes';
import { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * Canonical shape attached to `req.user` by JwtAuthGuard.
 * `id` and `sub` are aliases for the same user id so both
 * `@CurrentUser('id')` and `@CurrentUser('sub')` resolve correctly,
 * regardless of which guard authenticated the request.
 */
export interface AuthenticatedUser {
  id: string;
  sub: string;
  email: string;
  role: string;
  tokenVersion?: number;
}

interface RequestWithUser extends Request {
  user: AuthenticatedUser;
}

/**
 * JWT Authentication Guard
 * Validates JWT tokens from the Authorization header
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private reflector: Reflector,
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if the route is public
    const isPublic = this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new AuthException(
        ErrorCode.UNAUTHORIZED,
        'Missing authentication token',
      );
    }

    let payload: any;
    try {
      const secret = this.configService.get<string>('JWT_ACCESS_SECRET');

      if (!secret) {
        throw new AuthException(
          ErrorCode.UNAUTHORIZED,
          'JWT configuration is missing',
        );
      }

      payload = this.jwtService.verify(token, {
        secret,
      });
    } catch (error: unknown) {
      if (error instanceof AuthException) {
        throw error;
      }
      if (error instanceof Error && error.name === 'TokenExpiredError') {
        throw new AuthException(ErrorCode.TOKEN_EXPIRED, 'Token has expired');
      }
      throw new AuthException(ErrorCode.TOKEN_INVALID, 'Invalid token');
    }

    // Verify the token version against the current user record so that
    // password changes and "sign out everywhere" revoke outstanding access
    // tokens.
    const tokenVersion = typeof payload.tokenVersion === 'number' ? payload.tokenVersion : 0;

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, role: true, tokenVersion: true },
    });

    if (!user) {
      throw new AuthException(ErrorCode.TOKEN_INVALID, 'Invalid token');
    }

    if ((user.tokenVersion ?? 0) !== tokenVersion) {
      throw new AuthException(
        ErrorCode.TOKEN_INVALID,
        'Token has been revoked',
      );
    }

    // Single canonical req.user shape: id and sub are aliases of the same
    // user id, so @CurrentUser('id') and @CurrentUser('sub') both resolve.
    request.user = {
      id: user.id,
      sub: user.id,
      email: user.email,
      role: user.role,
      tokenVersion: user.tokenVersion ?? 0,
    };

    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      return undefined;
    }

    const [scheme, token] = authHeader.split(' ');
    return scheme === 'Bearer' ? token : undefined;
  }
}
