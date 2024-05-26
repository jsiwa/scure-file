import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto'
import type { Cipher, Decipher } from 'node:crypto'
import { createReadStream, createWriteStream, promises as fs } from 'node:fs'
import { pipeline } from 'node:stream'
import { promisify } from 'node:util'

const asyncPipeline = promisify(pipeline);

export type Algorithm =
  | 'aes-128-cbc'
  | 'aes-192-cbc'
  | 'aes-256-cbc'
  | 'aes-128-ctr'
  | 'aes-256-gcm'

export type EncryptionOptions = {
  algorithm: Algorithm;
  password: string;
};

interface ExtendedCipher extends Cipher {
  getAuthTag?(): Buffer;
}

interface ExtendedDecipher extends Decipher {
  setAuthTag?(tag: Buffer): this;
}

function isGCMAlgorithm(algorithm: string): algorithm is 'aes-256-gcm' {
  return algorithm === 'aes-256-gcm';
}

function getIVLength(algorithm: Algorithm): number {
  if (algorithm.startsWith('aes-')) {
    return 16;
  } else if (algorithm.startsWith('des-')) {
    return 8;
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

function getKeyLength(algorithm: Algorithm): number {
  switch (algorithm) {
    case 'aes-256-cbc':
    case 'aes-256-gcm':
      return 32;
    case 'aes-192-cbc':
      return 24;
    case 'aes-128-cbc':
    case 'aes-128-ctr':
      return 16;
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}

export async function encryptFileAsync(inputPath: string, outputPath: string, options: EncryptionOptions): Promise<void> {
  const { algorithm, password } = options;
  const keyLength = getKeyLength(algorithm);
  const key = scryptSync(password, 'salt', keyLength);
  const ivLength = getIVLength(algorithm);
  const iv = ivLength ? randomBytes(ivLength) : '';
  const cipher = createCipheriv(algorithm, key, iv) as ExtendedCipher;

  const readStream = createReadStream(inputPath);
  const writeStream = createWriteStream(outputPath);

  await asyncPipeline(readStream, cipher, writeStream);
  if (ivLength) {
    await fs.writeFile(`${outputPath}.iv`, iv);
  }
  if (isGCMAlgorithm(algorithm) && cipher.getAuthTag) {
    await fs.writeFile(`${outputPath}.tag`, cipher.getAuthTag());
  }
}

export async function decryptFileAsync(inputPath: string, outputPath: string, options: EncryptionOptions): Promise<void> {
  const { algorithm, password } = options;
  const keyLength = getKeyLength(algorithm);
  const key = scryptSync(password, 'salt', keyLength);
  const iv = getIVLength(algorithm) ? await fs.readFile(`${inputPath}.iv`) : '';
  const decipher = createDecipheriv(algorithm, key, iv) as ExtendedDecipher;

  if (isGCMAlgorithm(algorithm)) {
    const tag = await fs.readFile(`${inputPath}.tag`);
    decipher.setAuthTag && decipher.setAuthTag(tag);
  }

  const readStream = createReadStream(inputPath);
  const writeStream = createWriteStream(outputPath);

  await asyncPipeline(readStream, decipher, writeStream);
}

export async function encryptTextAsync(plainText: string, options: EncryptionOptions): Promise<string> {
  const { algorithm, password } = options;
  const keyLength = getKeyLength(algorithm);
  const key = scryptSync(password, 'salt', keyLength);
  const ivLength = getIVLength(algorithm);
  const iv = ivLength ? randomBytes(ivLength) : '';
  const cipher = createCipheriv(algorithm, key, iv) as ExtendedCipher;

  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  if (isGCMAlgorithm(algorithm) && cipher.getAuthTag) {
    const authTag = cipher.getAuthTag().toString('hex');
    return iv.toString('hex') + encrypted + authTag;
  }
  return iv.toString('hex') + encrypted;
}

export async function decryptTextAsync(encryptedText: string, options: EncryptionOptions): Promise<string> {
  const { algorithm, password } = options;
  const keyLength = getKeyLength(algorithm);
  const key = scryptSync(password, 'salt', keyLength);
  const ivLength = getIVLength(algorithm);
  const iv = ivLength ? Buffer.from(encryptedText.slice(0, ivLength * 2), 'hex') : '';
  const encrypted = encryptedText.slice(ivLength * 2, isGCMAlgorithm(algorithm) ? -32 : undefined);
  const decipher = createDecipheriv(algorithm, key, iv) as ExtendedDecipher;

  if (isGCMAlgorithm(algorithm)) {
    const authTag = Buffer.from(encryptedText.slice(-32), 'hex');
    decipher.setAuthTag && decipher.setAuthTag(authTag);
  }

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
