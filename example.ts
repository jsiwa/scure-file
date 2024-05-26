import { encryptTextAsync, decryptTextAsync } from './index'
import type { EncryptionOptions } from './index'

const text = 'Hello, world!'

const options: EncryptionOptions = {
  algorithm: 'aes-256-gcm',
  password: 'my-super-secret-password'
}

encryptTextAsync(text, options)
  .then(encryptedText => {
    console.log('Encrypted text:', encryptedText)

    decryptTextAsync(encryptedText, options)
      .then(decryptedText => console.log('decrypted text:', decryptedText))
      .catch(err => console.error(err))
  })
  .catch(err => console.error(err))