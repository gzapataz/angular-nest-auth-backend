import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-User.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginDto } from './dto/login.dt';
import { RegisterUserDto } from './dto/register-user.dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response.interface';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto ) {
      return this.authService.login( loginDto );
  }

  @Post('/register')
  register(@Body() registerUserDto: RegisterUserDto ) {
      return this.authService.register( registerUserDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll(@Request() req: Request) {
    const user = req['user']; // Only for learning purpose: Get user from request
    return this.authService.findAll();
  }

  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken( @Request() req: Request ): Promise<LoginResponse> {
    return this.authService.checkToken( req );
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
