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
