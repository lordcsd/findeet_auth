import { userRoles } from '../dtos/userRole.dto';
import { SharedEntity } from '../shared/shared.entity';
import { Entity, Column } from 'typeorm';
import { AuthProviders } from 'src/constants/authProviders';

@Entity()
export class User extends SharedEntity {
  @Column()
  email: string;

  @Column({ type: 'boolean', default: false })
  emailVerified: boolean;

  @Column()
  firstName: string;

  @Column({
    type: 'enum',
    enum: AuthProviders,
    default: AuthProviders.local,
  })
  authProvider: AuthProviders;

  @Column()
  lastName: string;

  @Column({ nullable: true })
  password: string;

  @Column({
    type: 'enum',
    enum: userRoles,
  })
  role: userRoles;

  @Column({ nullable: true })
  login_otp: string;

  @Column({ nullable: true })
  login_otp_expires: Date;
}
