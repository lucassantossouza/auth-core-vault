import { KeycloakConfigDto } from './config-dto.index';

describe('config-dto.index', () => {
  it('exporta KeycloakConfigDto', () => {
    expect(KeycloakConfigDto).toBeDefined();
    expect(new KeycloakConfigDto()).toBeInstanceOf(KeycloakConfigDto);
  });
});
