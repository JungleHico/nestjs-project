import { BadRequestException, Injectable } from '@nestjs/common';
import { UserService } from 'src/modules/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  async login({ username, password }: AuthDto): Promise<any> {
    const user = await this.userService.findOneByUsername(username);
    if (!user) {
      throw new BadRequestException('帐号不存在或密码错误');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new BadRequestException('帐号不存在或密码错误');
    }

    const { password: pass, ...result } = user.toJSON();
    return {
      ...result,
      token: this.jwtService.sign({ username: user.username }),
    };
  }

  async register({ username, password }: AuthDto) {
    // 加密
    const saltOrRounds = 10;
    const hash = await bcrypt.hash(password, saltOrRounds);

    const createUser = {
      username,
      password: hash,
      nickname: '',
      avatar: '',
    };
    return await this.userService.create(createUser);
  }
}
