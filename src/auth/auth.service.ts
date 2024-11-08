import { ConflictException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

import {CreateUserDto, LoginDto, RegisterDto, UpdateAuthDto} from './dto'


@Injectable()
export class AuthService {

  constructor(
    // Se injecta 
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService

  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    // Forma basica
    // const newUser = new this.userModel(createUserDto);
    // return newUser.save();

    try {

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel(
        {
          password: bcryptjs.hashSync(password, 10),
          ...userData
        }
      );

      // 1 Encriptar contraseña

      // 2 Guardar usuario

      // 3 Generar JWT

      await newUser.save();

      //De esta forma vemos q no se retorne la contraseña pero si vaya a la bd
      const { password:_, ...user} = newUser.toJSON();
      return user

    } catch (error) {
      if (error.code === 11000) {
        throw new ConflictException(`El usuario ${createUserDto.email} ya existe`);
      }
      throw new InternalServerErrorException('Falla');
    }

  }

  async register(registerDto: RegisterDto): Promise<LoginResponse>{

    const user = await this.create(registerDto);

    return {
      user: user,
      token: this.getJWTToken({id: user._id}) 
    }

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email})
    if (!user) {
      throw new UnauthorizedException('Credenciales invalidas - email')
    }

    if(!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Credenciales invalidas - password')
    }

    const {password:_, ...rest} = user.toJSON();

    return {
      user: rest,
      token: this.getJWTToken({id: user.id})
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
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

  getJWTToken(payload: JwtPayload){
    const token = this.jwtService.sign(payload)
    return token
  }
}
