import { Injectable } from '@nestjs/common';
@Injectable()
export class MockIntegrations {
  readonly mode = 'mock' as const;
  readonly providers = {
    sms: 'mock',
    payments: 'mock',
    identity: 'mock',
    maps: 'mock',
    storage: 'mock',
  } as const;
  describe() {
    return { mode: this.mode, providers: this.providers };
  }
}
