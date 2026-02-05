import * as guards from './index';

describe('guards index', () => {
  it('re-exporta AuthGuard, ResourceGuard e RoleGuard', () => {
    expect(guards.AuthGuard).toBeDefined();
    expect(guards.ResourceGuard).toBeDefined();
    expect(guards.RoleGuard).toBeDefined();
  });
});
