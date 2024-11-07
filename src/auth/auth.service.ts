import { ConflictException, Injectable, InternalServerErrorException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

@Injectable()
export class AuthService {

  constructor(
    // Se injecta 
    @InjectModel(User.name)
    private userModel: Model<User>

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

  findAll() {
    return `This action returns all auth`;
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
}
