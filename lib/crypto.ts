import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 12 bytes is standard for GCM
const TAG_LENGTH = 16; // 16 bytes is standard for GCM

function getEncryptionKey(): Buffer {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    throw new Error('ENCRYPTION_KEY is not defined in .env');
  }
  // Standardize the key length to exactly 32 bytes using SHA-256
  return crypto.createHash('sha256').update(key).digest();
}

/**
 * Encrypts a string and returns a colon-separated string: iv:authTag:encryptedText
 */
export function encryptText(text: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts a colon-separated encrypted string.
 * Falls back to the original text if decryption fails or format is invalid (for legacy data compatibility).
 */
export function decryptText(encryptedText: string): string {
  if (!encryptedText) return '';
  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    return encryptedText; // Fallback for unencrypted legacy data
  }

  try {
    const [ivHex, authTagHex, encryptedHex] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    // Quick length sanity checks
    if (iv.length !== IV_LENGTH || authTag.length !== TAG_LENGTH) {
      return encryptedText;
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    // Gracefully handle decryption failure and return original text
    console.error('Decryption failed, falling back to original text:', error);
    return encryptedText;
  }
}

/**
 * Encrypts a binary buffer and prepends the IV and Auth Tag.
 * Format: [12 bytes IV] [16 bytes Auth Tag] [encrypted data]
 */
export function encryptBuffer(buffer: Buffer): Buffer {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]);
}

/**
 * Decrypts a binary buffer that was encrypted via encryptBuffer.
 */
export function decryptBuffer(encryptedBuffer: Buffer): Buffer {
  if (encryptedBuffer.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error('Invalid encrypted buffer format');
  }

  const iv = encryptedBuffer.subarray(0, IV_LENGTH);
  const authTag = encryptedBuffer.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = encryptedBuffer.subarray(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(), iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
