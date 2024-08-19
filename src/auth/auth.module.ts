import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { envs } from 'src/config';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    JwtModule.register({
      global: true,
      secret: envs.jwtSecret,
      signOptions: { expiresIn: '2h' }
    })
  ]
})
export class AuthModule {}
