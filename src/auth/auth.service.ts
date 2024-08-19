import { JwtService } from '@nestjs/jwt';
import { PrismaClient } from '@prisma/client';
import { compareSync, hashSync } from 'bcrypt';
import { RpcException } from '@nestjs/microservices';
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';

import { envs } from 'src/config';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  
  private readonly logger = new Logger('AuthService');

  constructor(
    private readonly jwtService: JwtService
  ) {
    super();
  }
  
  onModuleInit() {
    this.$connect();
    this.logger.log('Database connected');
  }
  
  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
  
  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret
      })
      return {
        user: user,
        token: await this.signJWT(user)
      }
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token'
      })
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email: email
        }
      })
      if(user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists'
        })
      }
      const newUser = await this.user.create({
        data: {
          email: email,
          name: name,
          password: hashSync(password, 10)
        }
      })
      const { password: __, ...rest } = newUser;
      return {
        user: rest,
        token: await this.signJWT(rest)
      }
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email: email
        }
      })
      if(!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid'
        })
      }
      const isPasswordValid = compareSync(password, user.password);
      if(!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not valid'
        })
      }
      const { password: __, ...rest } = user;
      return {
        user: rest,
        token: await this.signJWT(rest)
      }
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message
      })
    }
  }
}
