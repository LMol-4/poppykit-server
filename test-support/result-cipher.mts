import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
// One fixture-owned key survives issuer reconstruction, like a host's durable protected key.
export function resultCipher() {
  const key = randomBytes(32);
  return {
    seal(value: string) { const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv); return Buffer.concat([iv, cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64url'); },
    open(value: string) { const bytes = Buffer.from(value, 'base64url'), cipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12)); cipher.setAuthTag(bytes.subarray(-16)); return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]).toString('utf8'); },
  };
}
