import { encryptFileAsync, decryptFileAsync, encryptTextAsync, decryptTextAsync } from './index'
import fs from 'node:fs/promises'
import { describe, it, expect, beforeAll, afterAll } from 'bun:test'
import type { EncryptionOptions, Algorithm } from './index'

const testFilePath = 'test.txt'
const encryptedFilePath = 'test.enc'
const decryptedFilePath = 'test.dec.txt'
const algorithms: Algorithm[] = [
  'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
  'aes-128-ctr', 'aes-256-gcm',
]
const password = 'my-super-secret-password'
const text = 'Hello, world!'

beforeAll(async () => {
  await fs.writeFile(testFilePath, 'This is a test file.')
})

afterAll(async () => {
  try {
    await fs.unlink(testFilePath)
  } catch (error) {
    console.error(`Error deleting ${testFilePath}:`, error)
  }
  try {
    await fs.unlink(encryptedFilePath)
  } catch (error) {
    console.error(`Error deleting ${encryptedFilePath}:`, error)
  }
  try {
    await fs.unlink(decryptedFilePath)
  } catch (error) {
    console.error(`Error deleting ${decryptedFilePath}:`, error)
  }
  try {
    await fs.unlink(`${encryptedFilePath}.iv`)
    await fs.unlink(`${encryptedFilePath}.tag`)
  } catch (error) {
    console.error(`Error deleting metadata files:`, error)
  }
})

describe('File Encryption and Decryption Tests', () => {
  algorithms.forEach(algorithm => {
    it(`should encrypt and decrypt file correctly using ${algorithm}`, async () => {
      const options: EncryptionOptions = { algorithm, password }

      console.log(`Starting file encryption with ${algorithm}...`)
      await encryptFileAsync(testFilePath, encryptedFilePath, options)
      console.log(`File encrypted successfully with ${algorithm}.`)

      console.log(`Starting file decryption with ${algorithm}...`)
      await decryptFileAsync(encryptedFilePath, decryptedFilePath, options)
      console.log(`File decrypted successfully with ${algorithm}.`)

      const originalContent = await fs.readFile(testFilePath, 'utf8')
      const decryptedContent = await fs.readFile(decryptedFilePath, 'utf8')

      expect(decryptedContent).toBe(originalContent)
    })
  })
})

describe('Text Encryption and Decryption Tests', () => {
  algorithms.forEach(algorithm => {
    it(`should encrypt and decrypt text correctly using ${algorithm}`, async () => {
      const options: EncryptionOptions = { algorithm, password }

      const encryptedText = await encryptTextAsync(text, options)
      const decryptedText = await decryptTextAsync(encryptedText, options)

      expect(decryptedText).toBe(text)
    })
  })
})
