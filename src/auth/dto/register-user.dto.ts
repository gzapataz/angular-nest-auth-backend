import { equal } from "assert";
import { IsEmail, IsString, MinLength } from "class-validator";


export class RegisterUserDto {
    
    @IsString()
    name: string;
    @IsEmail()
    email: string;
    @MinLength(6)
    password: string;
    @MinLength(6)
    password2: string;

}