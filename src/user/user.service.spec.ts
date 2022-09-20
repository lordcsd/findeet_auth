import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../app.module';
import { UserService } from './user.service';

describe('UserService', () => {
  let service: UserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    service = module.get<UserService>(UserService);
  });

  it('Should be defined', () => {
    expect(service).toBeDefined();
  });

  it('Return a user', async () => {
    expect(
      Object.keys(await service.getUserByEmail('dimgbachinonso@gmail.com')),
    ).toEqual(
      expect.arrayContaining([
        'id',
        'createdOn',
        'updateOn',
        'deletedOn',
        'createdBy',
        'updatedBy',
        'deletedBy',
        'email',
        'firstName',
        'lastName',
        'password',
        'role',
      ]),
    );
  });
});
