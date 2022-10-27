import {
  IsString,
  IsEnum,
  IsNotEmpty,
  IsEmail,
  IsDateString,
  IsNumber,
  IsOptional,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { StudentClassCategoryeEnum } from './studentClassCategory.DTO';
import { PasswordDTO } from './password.dto';
import { UserRoles } from 'src/dtos/userRole.dto';

export class signUpDTO extends PasswordDTO {
  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    type: String,
    description: 'User First name',
    default: 'John',
  })
  firstName: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    type: String,
    description: 'User Last name',
    default: 'Doe',
  })
  lastName: string;

  @IsNotEmpty({ message: 'Email cannot be empty' })
  @IsEmail({}, { message: 'Invalid Email' })
  @Transform(({ value }) => value.toLowerCase())
  @ApiProperty({
    type: String,
    description: 'User email',
    default: 'nicdos@gmail.com',
  })
  email: string;

  // @IsNotEmpty()
  // @IsEnum(UserRoles, {
  //   message: `userRole: Must be either ${Object.values(UserRoles).join(
  //     ' or ',
  //   )}`,
  // })
  // @ApiProperty({
  //   type: String,
  //   enum: UserRoles,
  //   description: 'User role',
  //   default: UserRoles.STUDENT,
  // })
  // role: UserRoles;
}

export class StudentSignUpDTO extends signUpDTO {
  @IsNotEmpty()
  @IsDateString({ message: 'studentDOB: Must be valid date' })
  @ApiProperty({ description: 'Students Day of Birth', type: Date })
  studentDOB: Date;

  @IsNotEmpty()
  @IsEnum(StudentClassCategoryeEnum, {
    message: `studentClassCategory: Must be ${Object.values(
      StudentClassCategoryeEnum,
    ).join(' or ')}`,
  })
  @ApiProperty({
    description: `${Object.values(StudentClassCategoryeEnum).join(' or ')}`,
    default: StudentClassCategoryeEnum.NURSERY,
  })
  studentClassCategory: StudentClassCategoryeEnum;

  @IsNotEmpty()
  @IsNumber({}, { message: 'studentClass: Must be a number' })
  @ApiProperty({ description: 'Students class', type: Number, default: 4 })
  studentClass: number;
}

export class ParentSignUpDTO extends signUpDTO {
  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    type: String,
    description: 'Parent Location',
    default: 'Lagos, Nigeria',
  })
  parentLocation: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  @ApiPropertyOptional({
    type: String,
    description: 'Parent"s home address',
    default: '20 Andrew road Ikoyi',
  })
  parentAddress: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  @ApiPropertyOptional({
    type: String,
    description: 'Parent spouse"s name ',
    default: 'Otamere',
  })
  parentSpouseName: string;
}

export class SchoolSignUpDTO extends signUpDTO {}
