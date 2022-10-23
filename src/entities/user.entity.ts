import { userRoles } from '../dtos/userRole.dto';
import { SharedEntity } from '../shared/shared.entity';
import { Entity, Column } from 'typeorm';
import { AuthProviders } from 'src/constants/authProviders';
import { StudentClassCategoryeEnum } from 'src/auth/dtos/studentClassCategory.DTO';

@Entity()
export class User extends SharedEntity {
  //common fields
  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column()
  email: string;

  @Column({ nullable: true })
  password: string;

  @Column({ type: 'boolean', default: false })
  emailVerified: boolean;

  @Column({
    type: 'enum',
    enum: AuthProviders,
    default: AuthProviders.local,
  })
  authProvider: AuthProviders;

  @Column({
    type: 'enum',
    enum: userRoles,
  })
  role: userRoles;

  @Column({ nullable: true })
  loginOtp: string;

  @Column({ nullable: true })
  loginOtpExpires: Date;

  @Column({ nullable: true })
  twoFactorAuthenticationCode: string;

  @Column({ nullable: true, type: 'enum', enum: StudentClassCategoryeEnum })
  studentCategory: StudentClassCategoryeEnum;

  //student specific fields
  @Column({ type: 'date', nullable: true })
  studentDOB: Date;

  @Column({ type: 'int', nullable: true })
  studentClass: number;

  //parent specific fields
  @Column({ nullable: true })
  parentLocation: string;

  @Column({ nullable: true })
  parentAddress: string;

  @Column({ nullable: true })
  parentSpouseName: string;
}
