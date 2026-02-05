import { validateSync } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { ValidateResponseDto } from './validate-response.dto';

const base = {
  sub: 'user-id',
  exp: 1769963193,
  iat: 1769962893,
  jti: 'b2a88ebe-a4bf-4620-842d-3c031834757d',
};

describe('ValidateResponseDto', () => {
  it('valida instância com campos obrigatórios', () => {
    const dto = plainToInstance(ValidateResponseDto, base);
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
  });

  it('valida instância com realm_access, resource_access e additionalClaims', () => {
    const dto = plainToInstance(ValidateResponseDto, {
      ...base,
      realm_access: { roles: ['offline_access', 'default-roles'] },
      resource_access: {
        account: { roles: ['manage-account', 'view-profile'] },
      },
      additionalClaims: {
        azp: 'orchestron-core',
        sid: '9641f0fa-ab1e-40f8-b093-f4c32ae163c2',
      },
    });
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
    expect(dto.realm_access?.roles).toEqual([
      'offline_access',
      'default-roles',
    ]);
    expect(dto.resource_access?.account?.roles).toEqual([
      'manage-account',
      'view-profile',
    ]);
    expect(dto.additionalClaims?.azp).toBe('orchestron-core');
  });

  it('valida instância só com realm_access (branch decorators 162-174)', () => {
    const dto = plainToInstance(ValidateResponseDto, {
      ...base,
      realm_access: { roles: ['role1'] },
    });
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
    expect(dto.realm_access).toEqual({ roles: ['role1'] });
  });

  it('valida instância só com resource_access (branch decorators)', () => {
    const dto = plainToInstance(ValidateResponseDto, {
      ...base,
      resource_access: { myclient: { roles: ['r1'] } },
    });
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
    expect(dto.resource_access?.myclient?.roles).toEqual(['r1']);
  });

  it('valida instância só com additionalClaims (branch decorators)', () => {
    const dto = plainToInstance(ValidateResponseDto, {
      ...base,
      additionalClaims: { custom: 'value' },
    });
    const errors = validateSync(dto);
    expect(errors).toHaveLength(0);
    expect(dto.additionalClaims).toEqual({ custom: 'value' });
  });
});
