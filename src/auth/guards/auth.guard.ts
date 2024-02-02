import { BadRequestException, CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor( 
    private jwtService: JwtService,
    private authService: AuthService
   ) {}

  async canActivate( context: ExecutionContext ): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if ( !token ) {
      throw new UnauthorizedException('No valid token provided');
    }
    try {
      const payload = await this.jwtService.verifyAsync(
        token,
        {
          secret: process.env.JWT_SEED
        }
      );
      // 💡 We're assigning the payload to the request object here
      // so that we can access it in our route handlers
      console.log({payload});
      const user = await this.authService.findUserById( payload.id );
      if ( !user ) {
        throw new UnauthorizedException("The user doesn't exists");
      }
      if ( !user.isActive) {
        throw new UnauthorizedException("The user is not active");
      }
      console.log(user);
      request['user'] = user;
      return true;
    } 
    catch ( error ) {
      throw new UnauthorizedException('Invalid Token');
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization'].split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

}
