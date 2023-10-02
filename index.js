import pkg from 'node-forge'
import { pbkdf2Sync } from 'pbkdf2'
const { pki, md } = pkg

export const createKeyPair = (name, pwd) => {
  const nHash = md.sha256.create().update(name, 'utf8').digest().getBytes().toString('base64')
  const pHash = md.sha256.create().update(pwd, 'utf8').digest().getBytes().toString('base64')
  const derivedKey = pbkdf2Sync(nHash + pHash, nHash, 4096, 32, 'sha512')
  const seed = derivedKey
  const { privateKey, publicKey } = pki.ed25519.generateKeyPair({ seed })
  return { privateKey, publicKey }
}

export const createIdentityTicket = (name, pwd, challenge) => {
  const keyPair = createKeyPair(name, pwd)
  const solve = solveChallenge(challenge, keyPair.privateKey)
  const ticket = {
    name,
    publicKey: keyPair.publicKey.toString('base64'),
    challengeAnswer: solve
  }

  const messageDigest = md.sha256.create().update(JSON.stringify(ticket), 'utf8').digest().getBytes().toString('base64')

  const signature = pki.ed25519.sign({
    message: messageDigest,
    encoding: 'utf8',
    privateKey: keyPair.privateKey
  })

  ticket.signature = signature.toString('base64')
  return ticket
}

export const verifyIdentityTicket = (ticket, challengeQuestion) => {
  try {
    const signature = Buffer.from(ticket.signature, 'base64')
    delete ticket.signature

    const messageDigest = md.sha256.create().update(JSON.stringify(ticket), 'utf8').digest().getBytes().toString('base64')

    const challengeDigest = md.sha256.create().update(challengeQuestion, 'utf8').digest().getBytes().toString('base64')
    const publicKey = Buffer.from(ticket.publicKey, 'base64')

    const verifySign = pki.ed25519.verify({
      message: messageDigest,
      encoding: 'utf8',
      signature,
      publicKey
    })

    const verifyChallenge = pki.ed25519.verify({
      message: challengeDigest,
      encoding: 'utf8',
      signature: Buffer.from(ticket.challengeAnswer, 'base64'),
      publicKey
    })

    return verifyChallenge && verifySign
  } catch {
    return false
  }
}

export const solveChallenge = (challenge, privateKey) => {
  const messageDigest = md.sha256.create().update(challenge.toString('base64')).digest().getBytes().toString('base64')
  const answer = pki.ed25519.sign({
    message: messageDigest,
    encoding: 'utf8',
    privateKey
  })
  return answer.toString('base64')
}
