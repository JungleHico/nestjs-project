import { IsOptional, IsString, IsUrl, MaxLength } from 'class-validator';

export class UpdateUserDto {
  @IsString()
  @IsOptional()
  @MaxLength(8)
  nickname: string;

  @IsString()
  @IsOptional()
  @IsUrl()
  avatar: string;
}
