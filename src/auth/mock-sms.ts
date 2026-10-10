import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { AuthSettings } from './settings';
import { seal } from './crypto';
export class MockSms {
  private readonly inbox = new Map<string, string>();
  constructor(
    private readonly settings: AuthSettings,
    private readonly capture = false,
  ) {
    if (capture && settings.env.NODE_ENV !== 'test') throw new Error('SMS capture is test-only');
  }
  async send(challengeId: string, code: string, expiresAt: Date): Promise<void> {
    if (this.capture) {
      this.inbox.set(challengeId, code);
      return;
    }
    if (this.settings.env.NODE_ENV !== 'development') return;
    const directory = path.resolve('.cache/mock-sms');
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(
      path.join(directory, `${challengeId}.json`),
      JSON.stringify({
        expiresAt: expiresAt.toISOString(),
        sealed: seal(this.settings.encryptionKey, code),
      }),
      { mode: 0o600 },
    );
  }
  capturedCode(challengeId: string): string | undefined {
    return this.inbox.get(challengeId);
  }
}
