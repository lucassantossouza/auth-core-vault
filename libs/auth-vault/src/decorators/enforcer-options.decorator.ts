import { META_ENFORCER_OPTIONS } from '../constants';
import { SetMetadata } from '@nestjs/common';
import { IEnforcerOptions } from '../interfaces';

/**
 * Sets enforcer options for the route or controller (ResourceGuard), e.g. policyEnforcementMode.
 * @param options - IEnforcerOptions (e.g. policyEnforcementMode: PolicyEnforcementMode.ENFORCING)
 * @example
 * @Resource('my-api')
 * @EnforcerOptions({ policyEnforcementMode: PolicyEnforcementMode.ENFORCING })
 * @Get() getData() { ... }
 */
export const EnforcerOptions = (options: IEnforcerOptions) =>
  SetMetadata(META_ENFORCER_OPTIONS, options);
