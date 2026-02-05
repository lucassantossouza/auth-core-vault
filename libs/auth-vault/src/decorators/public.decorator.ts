import { SetMetadata } from '@nestjs/common';

export const META_PUBLIC = 'public';

/**
 * Marks route or controller as public. AuthGuard does not require authentication; tokens may still be validated.
 */
export const Public = () => SetMetadata(META_PUBLIC, true);
