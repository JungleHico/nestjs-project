import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<any> {
    const { username } = createUserDto;
    const found = await this.userModel.findOne({
      username,
    });
    if (found) {
      throw new BadRequestException(`user ${username} is existed`);
    }

    const createUser = new this.userModel(createUserDto);
    const user = await createUser.save();
    const { password, __v, ...result } = user.toJSON(); // 移除多余字段
    return result;
  }

  async findAll(query: QueryWithPagination): Promise<User[]> {
    const { current = 1, pageSize = 10 } = query;

    return this.userModel
      .find()
      .select({ password: 0 })
      .skip(current - 1)
      .limit(+pageSize)
      .exec();
  }

  async findOne(id: string): Promise<User> {
    const user = await this.userModel
      .findOne({ _id: id })
      .select({ password: 0 })
      .exec();
    if (!user) {
      throw new NotFoundException(`user #${id} is not found`);
    }

    return user;
  }

  async findOneByUsername(username: string): Promise<User> {
    const user = await this.userModel.findOne({ username }).exec();
    return user;
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.userModel
      .findOneAndUpdate({ _id: id }, { $set: updateUserDto }, { new: true })
      .select({ password: 0 })
      .exec();
    if (!user) {
      throw new NotFoundException(`user #${id} is not found`);
    }

    return user;
  }

  async remove(id: string): Promise<User> {
    const user = await this.userModel
      .findOne({ _id: id })
      .select({ password: 0 });
    if (!user) {
      return null;
    }
    return await user.remove();
  }
}
