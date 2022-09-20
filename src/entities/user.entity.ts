import { userRoles } from 'src/dtos/userRole.dto';
import { SharedEntity } from 'src/shared/shared.entity';
import { Entity, Column } from 'typeorm';

@Entity()
export class User extends SharedEntity {
  @Column()
  email: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column()
  password: string;

  @Column({
    type: 'enum',
    enum: userRoles,
  })
  role: userRoles;
}
