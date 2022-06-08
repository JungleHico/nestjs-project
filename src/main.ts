import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 全局路由前缀
  app.setGlobalPrefix('api');

  // 全局验证管道
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // 过滤用户输入的无关字段
      // forbidNonWhitelisted: true, // 禁止用户输入无关字段
      // transform: true, // 自动类型转换
    }),
  );
  await app.listen(3000);
}
bootstrap();
