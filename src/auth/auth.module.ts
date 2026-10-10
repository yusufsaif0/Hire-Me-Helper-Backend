import { Module } from '@nestjs/common';
import { backendRole } from '../environment';
import { AuthSettings, type BackendRole } from './settings';
import { AuthRepository } from './repository';
import { MockSms } from './mock-sms';
import { AuthService } from './service';
import { AccessGuard } from './http';
import { AdminAuthController } from './admin.controller';
import { MobileAuthController } from './mobile.controller';
@Module({
  controllers:
    (backendRole as BackendRole) === 'ADMIN' ? [AdminAuthController] : [MobileAuthController],
  providers: [
    { provide: AuthSettings, useFactory: () => new AuthSettings(backendRole) },
    {
      provide: AuthRepository,
      useFactory: (settings: AuthSettings) => new AuthRepository(settings),
      inject: [AuthSettings],
    },
    {
      provide: MockSms,
      useFactory: (settings: AuthSettings) => new MockSms(settings),
      inject: [AuthSettings],
    },
    {
      provide: AuthService,
      useFactory: (settings: AuthSettings, repo: AuthRepository, sms: MockSms) =>
        new AuthService(settings, repo, sms),
      inject: [AuthSettings, AuthRepository, MockSms],
    },
    AccessGuard,
  ],
  exports: [AuthService, AuthRepository, AuthSettings, MockSms],
})
export class AuthModule {}
