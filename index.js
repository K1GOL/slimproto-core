import pkg from 'node-forge'
import { pbkdf2Sync } from 'pbkdf2'
const { pki, md, random, util } = pkg

// Version of protocol implemented.
export const slimprotoVersion = '0.2'

// Creates a key pair for a given name and password.
// Return format (bytes):
// [Private key, 32 bytes][Public key, 32 bytes]
// Length 64 bytes.
export const createKeyPair = (name, pwd) => {
  // Trim name to max 65535 bytes.
  const nameBytes = Buffer.from(name, 'utf8').subarray(0, 65535)
  // Hash for name.
  const nHash = Buffer.from(md.sha256.create().update(nameBytes.toString('utf8'), 'utf8').digest().toHex(), 'hex')
  // Hash for password.
  const pHash = Buffer.from(md.sha256.create().update(pwd, 'utf8').digest().toHex(), 'hex')

  // Calculate derived key.
  // Input is (bytes): [nHash][pHash]
  // Salt is (bytes): [nHash]
  // Iterations is: 4069
  // Key length is: 64 byte
  // Hash algorithm is: SHA-256
  const pbkdfPassword = Buffer.concat([nHash, pHash])
  const derivedKey = pbkdf2Sync(pbkdfPassword, nHash, 4096, 64, 'sha256')
  const { privateKey, publicKey } = pki.ed25519.generateKeyPair({ seed: derivedKey })
  return Buffer.concat([privateKey, publicKey])
}

// Converts a buffer key pair with concatenated public and private key to an object with a public and private key property.
export const keyPairToObject = (keyPair) => {
  const privateKey = Buffer.alloc(32)
  const publicKey = Buffer.alloc(32)

  keyPair.copy(privateKey, 0, 0, 32)
  keyPair.copy(publicKey, 0, 32, 64)

  return {
    privateKey,
    publicKey
  }
}

// Creates an identity ticket for a given name, password and challenge.
// Return format (bytes):
// [Name length, 2 bytes][Name, n <= 65535 bytes][Public key, 32 bytes][Challenge answer, 64 bytes][Signature for preceding content, 64 bytes]
// Length n + 162 bytes.
export const createIdentityTicket = (name, pwd, challenge) => {
  const keyPair = keyPairToObject(createKeyPair(name, pwd))
  const solve = solveChallenge(challenge, keyPair.privateKey)
  // Trim name to max 65535 bytes.
  const nameBytes = Buffer.from(name, 'utf8').subarray(0, 65535)
  // Get name length.
  const nameLength = Buffer.alloc(2)
  nameLength.writeUInt16LE(nameBytes.byteLength, 0)

  // Sign ticket contents.
  const unsignedTicket = Buffer.concat([nameLength, nameBytes, keyPair.publicKey, solve])
  const ticketDigest = Buffer.from(md.sha256.create().update(unsignedTicket.toString('utf8'), 'utf8').digest().toHex(), 'hex')

  const signature = pki.ed25519.sign({
    message: ticketDigest,
    encoding: 'binary',
    privateKey: keyPair.privateKey
  })

  return Buffer.concat([unsignedTicket, signature])
}

// Converts a buffer ticket with concatenated data to an object with a appropriate properties.
export const ticketToObject = (ticket) => {
  const nameLength = ticket.readUInt16LE(0)

  const name = Buffer.alloc(nameLength)
  const publicKey = Buffer.alloc(32)
  const challengeAnswer = Buffer.alloc(64)
  const signature = Buffer.alloc(64)

  ticket.copy(name, 0, 2, 2 + nameLength)
  ticket.copy(publicKey, 0, nameLength + 2, nameLength + 2 + 32)
  ticket.copy(challengeAnswer, 0, nameLength + 34, nameLength + 34 + 64)
  ticket.copy(signature, 0, nameLength + 98, nameLength + 98 + 64)

  return {
    nameLength,
    name,
    publicKey,
    challengeAnswer,
    signature
  }
}

// Verifies an identity ticket by validating the signature.
export const verifyIdentityTicket = (ticket, challengeQuestion) => {
  try {
    const parsedTicket = ticketToObject(ticket)

    // Calculate hash.
    const unsignedTicket = Buffer.alloc(parsedTicket.nameLength + 98)
    ticket.copy(unsignedTicket, 0, 0, parsedTicket.nameLength + 98)
    const messageDigest = Buffer.from(md.sha256.create().update(unsignedTicket.toString('utf8'), 'utf8').digest().toHex(), 'hex')

    const challengeDigest = Buffer.from(md.sha256.create().update(challengeQuestion.toString('utf8'), 'utf8').digest().toHex(), 'hex')

    const verifySign = pki.ed25519.verify({
      message: messageDigest,
      encoding: 'binary',
      signature: parsedTicket.signature,
      publicKey: parsedTicket.publicKey
    })

    const verifyChallenge = pki.ed25519.verify({
      message: challengeDigest,
      encoding: 'binary',
      signature: parsedTicket.challengeAnswer,
      publicKey: parsedTicket.publicKey
    })

    return verifyChallenge && verifySign
  } catch {
    console.log('Caught')
    return false
  }
}

// Solves a given challenge with a private key.
// Return format (bytes):
// [Challenge answer, 64 bytes]
// Length 64 bytes.
export const solveChallenge = (challenge, privateKey) => {
  const messageDigest = Buffer.from(md.sha256.create().update(challenge.toString('utf8'), 'utf8').digest().toHex(), 'hex')
  const answer = pki.ed25519.sign({
    message: messageDigest,
    encoding: 'binary',
    privateKey
  })
  return answer
}

// Generates a random challenge.
export const generateRandomChallenge = (length = 512) => {
  return Buffer.from(util.bytesToHex(random.getBytesSync(length)), 'hex')
}
