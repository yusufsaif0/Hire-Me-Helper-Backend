import { AuthModule } from './auth/auth.module';
import { Module } from '@nestjs/common';
import { HealthController } from './health.controller';
import { MockIntegrations } from './integrations/mock-integrations';
@Module({ imports: [AuthModule], controllers: [HealthController], providers: [MockIntegrations] })
export class AppModule {}
