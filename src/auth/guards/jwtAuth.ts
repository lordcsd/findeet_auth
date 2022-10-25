import { AuthGuard } from '@nestjs/passport';
import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { UserRoles } from '../../dtos/userRole.dto';

export class JWTGuard extends AuthGuard('jwt') {
  role: UserRoles;
  constructor(private userRole: UserRoles) {
    super();
    this.role = userRole;
  }

  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err, user, info, context: ExecutionContext) {
    console.log('this.role: ', this.role);
    if (!user) {
      throw new UnauthorizedException();
    }
    if ((user && user.role === this.role) || typeof this.role == 'object') {
      context.switchToHttp().getRequest().headers['user'] = user;
      return user;
    }
    throw new UnauthorizedException();
  }
}
