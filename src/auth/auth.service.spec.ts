import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../app.module';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('Authenticate user', async () => {
    expect(
      Object.keys(
        await service.login({
          email: 'dimgbachinonso@gmail.com',
          password: 'Anambra/76Awka',
        }),
      ),
    ).toEqual(expect.arrayContaining(['access_token']));
  });

  it('sign up method exists', () => expect(service.signUp).toBeDefined);

  it('validate Users', async () => {
    expect(
      Object.keys(
        await service.validate('dimgbachinonso@gmail.com', 'Anambra/76Awka'),
      ),
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
