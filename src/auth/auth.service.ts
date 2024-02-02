import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException, Request } from '@nestjs/common';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';
import { RegisterUserDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create( createUserDto: CreateUserDto ): Promise<User> {
    try {
      const { password, ...userData } = createUserDto; 

      // 1-encrypt password
      const newUser = new this.userModel( {
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      } );
      // 2-save user
      await newUser.save();
      const { password:_, ...returnedUser } = newUser.toJSON();
      return returnedUser;
    }
    catch( error ) {
      if ( error.code === 11000 ) {
        throw new BadRequestException( `${ createUserDto.email } already exists` );
      } 
      throw new InternalServerErrorException(`Backend error contact the administrator ${ error.message }`);
    }
  }

  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    
    const { email, password } = loginDto;
    const user = await this.userModel.findOne( { email });

    if ( !user ) {
      throw new UnauthorizedException(' Not valid credentials - email');
    }

    if ( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException(' Not valid credentials - password');
    }

    const { password:_, ...userRemainder } = user.toJSON();

    return {
      user: userRemainder,
      token: this.getJwtToken( { id: user.id } ),
    }
    
    /*
    * user {_id, name, email, roles ,}
    * Token -> Json Web Token
    */
  }

  async register( registerUserDto: RegisterUserDto ): Promise<LoginResponse> {
    const { password2, ...userToRegister  } = registerUserDto;
    console.log(userToRegister)
    if ( password2 !== userToRegister.password ) {
      throw new BadRequestException('Passwords must be equal')
    }

    const newUser = await this.create( userToRegister );
    
    return {
      user: newUser,
      token: this.getJwtToken( { id: newUser._id })
    }
  }

  findAll():Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: number) {
    const user = await this.userModel.findById( id );
    const { password, ...userRemainder } = user.toJSON();
    return userRemainder;
  }

  async checkToken( req: Request ) {
    const user:User = req['user'];
    return {
      user: user,
      token: this.getJwtToken( { id: user._id } )
    } 
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload ) {
    const token = this.jwtService.sign( payload );
    return token;
  }
}
