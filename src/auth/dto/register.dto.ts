import { IsEmail, isObject, IsString, MinLength } from "class-validator";

export class RegisterDto {

    @IsString()
    name: string;

    @IsEmail()
    email: string;

    @MinLength(6)
    password: string;

}