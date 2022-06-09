# NestJS 入门文档



## 简介

Nest（NestJS）是一款用于构建高效的，可扩展的 Node.js 服务端应用程序框架。它使用渐进式 JavaScript，内置并且完全支持 TypeScript（但仍支持开发者使用纯 JavaScript 进行编程），结合了 OOP（面向对象编程），FP（函数式编程）和 FRP（函数式响应编程）的元素。

在底层，Nest 使用了健壮的 HTTP 服务器框架，如 Express（默认）和 Fastify。Nest 为这些框架提供了一定程度的抽象，不过也向开发者暴露了它们的 API，这样开发者就能使用各个平台的第三方模块。



## 快速上手

### 安装

首先全局安装脚手架：

```sh
npm i -g @nestjs/cli
```

然后使用脚手架初始化项目：

```sh
nest new project-name
```

初始化项目时脚手架会为我们安装相关依赖，所以创建项目的过程可能比较久，建议使用 yarn 构建项目。



### 启动

项目创建完之后，打开项目所在目录，运行命令启动项目：

```sh
npm run start:dev
```

`start:dev` 命令会构建开发环境项目，并通过 `watch` 监听文件的变化，如果文件被修改，会自动重启服务。

接着我们使用 [Postman](https://www.postman.com)，请求 http://localhost:3000，返回“Hello World!”，证明请求成功。



### Nest 服务做了哪些事（Controller/Service/Module）？

为什么我们访问 http://localhost:3000，就会返回“Hello World!”，Nest 服务到底做了哪些事呢？

首先我们打开 `src/main.ts` ，这是项目的入口文件：

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
```

从这部分代码我们可以推断，Nest 通过一个工厂方法，创建了一个和 `AppModule` 相关的 `app` 实例，该实例监听了 3000 端口。

接着我们打开 `src/app.module.ts` ，看下这个 `AppModule` ：

```typescript
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
  imports: [],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

这里通过 [TypeScript 装饰器](https://www.tslang.cn/docs/handbook/decorators.html) ，为 `AppModule` 这个类注入了 `AppController` 和 `AppService` 。    

然后我们再看下 `src/app.controller.ts` ：

```typescript
import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
```

 `AppController` 这个类被一个 `@Controller ` 装饰器修饰，类中定义了一个 `getHello` 方法，该方法被 `@Get` 修饰，这里就是我们处理 GET 请求的逻辑，可以看出，Controller 就是用于处理路由。但是这里并没有直接返回“Hello World!”，而是将业务放到了 `src/app.service.ts` 中：

```typescript
import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }
}
```

为什么我们不在 `AppController` 中直接返回结果，而要另外通过 `AppService` ，这是否多此一举呢？当然不是，实际开发中，我们可能需要定义了多个路由，如果我们把路由处理和具体业务内容都放在 Controller，就会显得庞杂而且难以复用，因此，我们应该将业务处理放在 Controller 中实现，而具体业务应该放在 Service 中。

我们再回过头看 `AppModule` ，顾名思义，Module 就是模块，是指一系列密切相关的内容，比如和应用相关的内容放在 `app` 模块中，和用户相关的内容放在 `user` 模块中，这样就有利于项目的维护。



## 中间件

**日志中间件**

简单日志实现：

```typescript
// src/common/middleware/logger.middleware.ts
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import * as dayjs from 'dayjs';

@Injectable()
export class LoggerMiddleWare implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    next();
    
    // 日志
    const { method, path: reqPath } = req;
    const date = dayjs();
    const logFold = path.resolve(__dirname, '../../../logs');
    const fileName = `${date.format('YYYYMMDD')}.log`;
    const logData = `[${date.format(
      'YYYY-MM-DD HH:mm:ss',
    )}] ${method} ${reqPath}`;
    console.log(logData); // 控制台打印日志
    try {
      // 保存日志文件
      if (!fs.existsSync(logFold)) {
        fs.mkdirSync(logFold);
      }
      fs.writeFileSync(`${logFold}/${fileName}`, logData + '\n', {
        flag: 'a+',
      });
    } catch (error) {
      console.error(error);
    }
  }
}
```

```typescript
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { LoggerMiddleWare } from './common/middleware/logger.middleware';

@Module({
  imports: [
	// ...
  ],
})
export class AppModule implements NestModule {
  // 配置中间件
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoggerMiddleWare).forRoutes('');
  }
}
```

使用 log4js 实现完善日志参考：[Nest.js 从零到壹系列（四）：使用中间件、拦截器、过滤器打造日志系统](https://juejin.cn/post/6844904098689449998)



## 异常处理（Exception）

**基础异常类 HttpException**

`throw new HttpException('xxx is not found', HttpStatus.NOT_FOUND)`



**内置异常**类

`throw new NotFoundException('xxx is not found')`



**异常过滤器**

全局异常过滤器：

```typescript
// src/common/filters/http-exception.filter.ts
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
} from '@nestjs/common';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    let status = exception.getStatus();
    const exceptionRes: any = exception.getResponse();
    let msg = exceptionRes.message.toString(); // 错误信息
    let code = 1; // 自定义错误码

    switch (status) {
      // TODO 处理不同错误
      default:
        break;
    }

    response.status(status).json({
      code,
      msg,
    });
  }
}
```

```typescript
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from 'src/common/filters/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 全局过滤器
  app.useGlobalFilters(new HttpExceptionFilter());

  await app.listen(3000);
}
bootstrap();
```





## 管道（Pipe）

管道功能：数据转换和数据验证

安装类验证器：

```sh
npm i --save class-validator class-transformer
```

修改 DTO：

```typescript
import { IsString } from 'class-validator';

export class CreateBookDto {
  @IsString()
  readonly name: string;

  @IsString()
  readonly author: string;

  @IsString()
  readonly press: string;
}
```

使用管道：

局部：`@UsePipes(new ValidationPipe())`

全局：

```typescript
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // 过滤用户输入的无关字段
      // forbidNonWhitelisted: true, // 禁止用户输入无关字段
      transform: true, // 自动类型转换
    }),
  );
```



## 拦截器

**响应拦截**

```typescript
// src/common/intercaptor/response.interceptor.ts
import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { map, Observable } from 'rxjs';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  intercept(
    context: ExecutionContext,
    next: CallHandler<any>,
  ): Observable<any> | Promise<Observable<any>> {
    return next.handle().pipe(
      map((data) => {
        return {
          data,
          code: 0,
          msg: 'success',
        };
      }),
    );
  }
}
```

```typescript
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ResponseInterceptor } from 'src/common/interceptor/response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 全局拦截器
  app.useGlobalInterceptors(new ResponseInterceptor());

  await app.listen(3000);
}
bootstrap();
```



## 数据库

> 这里以 MongoDB 为例，使用 mongoose 连接数据库，其他数据库，例如 MySQL，建议通过 TypeORM 连接数据库（TypeORM 对 MongoDB 支持并不友好）。



### 安装 MongoDB

### 启动

安装路径的 bin 目录下执行：

```sh
mongod --dbpath=C:\data\db
```

打开 MongoDBCompass，连接数据库

### NestJS 连接 MongoDB

#### 安装依赖

```sh
npm install --save @nestjs/mongoose mongoose
npm install --save-dev @types/mongoose
```

#### 使用 MongooseModule 连接数据库

```typescript
// src/app.module.ts
@Module({
  imports: [
    MongooseModule.forRoot('mongodb://localhost:27017/test') // 连接数据库
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

#### 定义 Schema

```typescript
// src/book/book.schema.ts
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class Book extends Document {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  author: string;

  @Prop({ required: true })
  press: string;
}

export type BookDocument = Book & Document;

export const BookSchema = SchemaFactory.createForClass(Book);
```

#### Module 中注册 Schema

```typescript
// src/book/book.module.ts
import { MongooseModule } from '@nestjs/mongoose';
import { Book, BookSchema } from './book.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Book.name, schema: BookSchema }]),
  ],
  controllers: [BookController],
  providers: [BookService],
})
export class BookModule {}
```

#### Service 中通过 @InjectModel() 注册 Model，进行数据操作

```typescript
// src/bok/book.service.ts
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Book, BookDocument } from './book.schema';

@Injectable()
export class BookService {
  constructor(@InjectModel('Book') private readonly bookSchema: Model<BookDocument>) {}
}
```



## 路由守卫和鉴权

鉴权应当包含两部分：

1. 对于注册/登录等接口，使用 local 策略校验帐号密码
2. 其他接口，使用 jwt 策略校验请求头是否携带 token 以及 token 是否有效

需要安装 passport 相关的依赖：

```sh
npm install --save @nestjs/passport passport passport-jwt passport-local
npm install --save-dev @types/passport-jwt @types/passport-local
```



### local

#### UserModule

auth 模块依赖 user 模块来查询用户相关的数据，因此需要先创建 user 模块：

```typescript
// src/modules/user/user.module.ts
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './user.schema';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]), // 指定数据库集合以及schema
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService], // 需要将UserService导出，供auth模块注入使用
})
export class UserModule {}
```

```typescript
// src/modules/user/user.schema.ts
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
  @Prop({ required: true })
  username: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: '' })
  nickname: string;

  @Prop({ default: '' })
  avatar: string;

  @Prop({ select: false })
  __v: number;
}

export type UserDocument = User & Document;

export const UserSchema = SchemaFactory.createForClass(User);
```

定义 DTO：

```typescript
// src/modules/user/dto/create-user.dto.ts
import {
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  IsUrl,
} from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  username: string;

  @IsNotEmpty()
  @IsString()
  password: string;

  @IsString()
  @IsOptional()
  @MaxLength(8)
  nickname: string;

  @IsString()
  @IsUrl()
  @IsOptional()
  avatar: string;
}
```

`UserService` 中添加创建用户和查找用户的方法：

```typescript
// src/modules/user/user.service.ts
import {
  Injectable,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
  ) {}

  // 新增用户
  async create(createUserDto: CreateUserDto): Promise<any> {
    const { username } = createUserDto;
    const found = await this.userModel.findOne({
      username,
    });
    if (found) {
      throw new BadRequestException('该用户已存在');
    }

    const createUser = new this.userModel(createUserDto);
    const user = await createUser.save();
    const { password, __v, ...result } = user.toJSON(); // 移除多余字段
    return result;
  }

  // 根据用户名查找用户
  async findOneByUsername(username: string): Promise<User> {
    const user = await this.userModel.findOne({ username }).exec();
    return user;
  }
}
```

#### 定义 local 策略

```typescript
// src/modules/auth/local.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super();
  }

  async validate(username: string, password: string) {
    if (!username || !password) {
      return false;
    }
    return { username, password };
  }
}
```

#### AuthModule

注入之前定义的 user 模块和本地策略到 auth 模块中：

```typescript
import { Module } from '@nestjs/common';
import { UserModule } from 'src/modules/user/user.module';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './local.strategy';

@Module({
  imports: [
    UserModule,
    PassportModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy],
})
export class AuthModule {}
```

定义 DTO：

```typescript
// src/modules/auth/dto/auth.dto.ts
import { IsString, IsNotEmpty } from 'class-validator';

export class AuthDto {
  @IsNotEmpty()
  @IsString()
  readonly username: string;

  @IsNotEmpty()
  @IsString()
  readonly password: string;
}
```

AuthService 中定义登录和注册方法：

```typescript
// src/modules/auth/auth.service.ts
import { BadRequestException, Injectable } from '@nestjs/common';
import { UserService } from 'src/modules/user/user.service';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
  ) {}

  // 登录
  async login({ username, password }: AuthDto): Promise<any> {
    const user = await this.userService.findOneByUsername(username);
    if (!user || user.password !== password) {
      throw new BadRequestException('帐号不存在或密码错误');
    }

    const { password: pass, ...result } = user.toJSON();
    return {
      ...result,
      token: this.jwtService.sign({ username: user.username }), // 返回token
    };
  }

  // 注册
  async register({ username, password }: AuthDto) {
    const createUser = {
      username,
      password,
      nickname: '',
      avatar: '',
    };
    return await this.userService.create(createUser);
  }
}
```

`AuthController` 中定义路由，并通过 `@UseGuards` 装饰器，启用路由守卫以及本地策略：

```typescript
import { Controller, UseGuards, Post, Body } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('auth')
@UseGuards(AuthGuard('local'))
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 登录
  @Post('login')
  async login(@Body() authDto: AuthDto) {
    return this.authService.login(authDto);
  }

  // 注册
  @Post('register')
  async register(@Body() authDto: AuthDto) {
    return this.authService.register(authDto);
  }
}
```



### jwt

对于需要鉴权的接口，需要 jwt 策略校验 token。

#### 定义 jwt 策略

首先，定义 secretKey：

```typescript
// src/modules/auth/constants.ts
export const jwtConstants = {
  secret: 'secretKey',
};
```

定义 jwt 策略：

```typescript
// src/modules/auth/jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtConstants } from './constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,
    });
  }
  async validate(payload: any) {
    return { username: payload.username }; // 返回值需要与jwt.sign传递的参数格式一致
  }
}
```

#### AuthModule

将 `JwtStragety` 注入到 auth 模块中：

```typescript
import { Module } from '@nestjs/common';
import { UserModule } from 'src/modules/user/user.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './local.strategy';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UserModule,
    PassportModule,
    JwtModule.register({
      secret: jwtConstants.secret,
      signOptions: { expiresIn: '1h' }, // token过期时间
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
})
export class AuthModule {}
```

#### UserModule

我们在 user 模块中，定义查看所有用户的服务和路由：

```typescript
// src/modules/user/user.service.ts
import {
  Injectable,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';

@Injectable()
export class UserService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
  ) {}

  // ...

  // 查找所有用户
  async findAll(): Promise<User[]> {
    return this.userModel
      .find()
      .select({ password: 0 })
      .exec();
  }
}
```

```typescript
import {
  Controller,
  UseGuards,
  Get,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { UserService } from './user.service';

@Controller('user')
@UseGuards(AuthGuard('jwt'))
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('list')
  async findAll() {
    return this.userService.findAll();
  }
}
```

通过 `@UseGuards` 装饰器，对 user 相关路由启用路由守卫和 jwt 策略。

#### 验证

打开 Postman，访问 `GET /user/list`，返回 401 未授权，调用登录接口，将返回的 token 添加到请求头部，成功返回数据。



## bcrypt 加密

对用户密码进行加密

安装：

```sh
npm i bcrypt
npm i -D @types/bcrypt
```

生成 hash 值：

```js
import * as bcrypt from 'bcrypt';

const saltOrRounds = 10;
const password = 'password';
const hash = await bcrypt.hash(password, saltOrRounds);
```

校验：

```js
const isMatch = await bcrypt.compare(password, hash);
```



## Swapper 文档生成器





