import { AuthGuard } from '@nestjs/passport';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { userRoles } from '../../dtos/userRole.dto';

export class ParentAuthGuard extends AuthGuard('jwt') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err, user, info, context: ExecutionContext) {
    if (!user) {
      throw new UnauthorizedException();
    }
    if (user && user.role === userRoles.PARENT) {
      return user;
    }
    throw new UnauthorizedException();
  }
}
