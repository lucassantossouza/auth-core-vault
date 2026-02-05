import { validateSync } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { LogoutCredentialsDto } from './logout-credentials.dto';

describe('LogoutCredentialsDto', () => {
  it('deve validar quando só refreshToken é informado', () => {
    const dto = plainToInstance(LogoutCredentialsDto, {
      refreshToken: 'my-refresh-token',
    });
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
  });

  it('deve validar quando só accessToken é informado', () => {
    const dto = plainToInstance(LogoutCredentialsDto, {
      accessToken: 'my-access-token',
    });
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
  });

  it('deve falhar quando nenhum token é informado', () => {
    const dto = plainToInstance(LogoutCredentialsDto, {});
    const errors = validateSync(dto);
    expect(errors.length).toBeGreaterThan(0);
    const messages = errors.flatMap((e) => Object.values(e.constraints ?? {}));
    expect(
      messages.some(
        (m) => m.includes('refreshToken') || m.includes('accessToken'),
      ),
    ).toBe(true);
  });

  it('deve falhar quando refreshToken está vazio e accessToken não informado', () => {
    const dto = plainToInstance(LogoutCredentialsDto, { refreshToken: '' });
    const errors = validateSync(dto);
    expect(errors.length).toBeGreaterThan(0);
  });
});
