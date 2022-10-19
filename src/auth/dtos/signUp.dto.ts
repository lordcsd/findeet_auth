import {
  IsString,
  IsEnum,
  IsNotEmpty,
  Matches,
  MinLength,
  IsEmail,
  IsDate,
  IsNumberString,
  IsDateString,
  IsNumber,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { userRoles } from '../../dtos/userRole.dto';
import { ApiProperty } from '@nestjs/swagger';
import { StudentClassCategoryeEnum } from './studentClassCategory.DTO';

export class signUpDTO {
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

  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  @Matches(/(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9])(?=.{8,})/, {
    message: 'password too weak',
  })
  @ApiProperty({
    type: String,
    description: "User's secure pawword",
    default: 'ckjsdhcuisjdu7y12%^',
  })
  password: string;
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

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    type: String,
    description: 'Parent"s home address',
    default: '20 Andrew road Ikoyi',
  })
  parentAddress: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    type: String,
    description: 'Parent spouse"s name ',
    default: 'Otamere',
  })
  parentSpouseName: string;
}

export class SchoolSignUpDTO extends signUpDTO {}
