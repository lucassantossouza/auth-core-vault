import { TokenValidation } from './token-validation.const';

describe('token-validation.const', () => {
  it('exporta enum TokenValidation com ONLINE e OFFLINE', () => {
    expect(TokenValidation.ONLINE).toBe('online');
    expect(TokenValidation.OFFLINE).toBe('offline');
  });
});
