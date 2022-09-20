import { Column, PrimaryGeneratedColumn } from 'typeorm';

export class SharedEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdOn: Date;

  @Column({ nullable: true, type: 'timestamp' })
  updateOn: Date;

  @Column({ nullable: true, type: 'timestamp' })
  deletedOn?: Date;

  @Column({ nullable: true })
  createdBy?: string;

  @Column({ nullable: true })
  updatedBy?: string;

  @Column({ nullable: true })
  deletedBy?: string;
}
