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
    const status = exception.getStatus();
    const exceptionRes: any = exception.getResponse();
    let message = exceptionRes.message;

    switch (status) {
      case 400:
        if (Array.isArray(message)) {
          message = message.join(', ');
        } else {
          message = '参数错误';
        }
        break;
      case 401:
        message = '身份过期，请重新登录';
        break;
      case 404:
        message = '未找到';
        break;
      default:
        break;
    }

    response.status(status).json({
      statusCode: status,
      message,
    });
  }
}
