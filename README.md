# slimproto-core

### Peer-to-peer identity management protocol.

With _Slim_, peers can verify each other's identities without a central identity authority. Keys are derived from credentials that are easy to store and even remember.

#### Contents

- [Description](https://github.com/K1GOL/slimproto-core#description)
- [Documentation](https://github.com/K1GOL/slimproto-core#documentation)
- [Testing](https://github.com/K1GOL/slimproto-core#testing)
- [Example usage](https://github.com/K1GOL/slimproto-core#example-usage)

## Description

The Slim protocol is a peer-to-peer identity management protocol that allows peers to verify each other's identities without a central identity authority.

Each user creates an identity ticket with a public name and a private password. From these, an Ed25519 key pair is generated, which is used to identify the user.

For verification of the identity of a peer, the peer presents an identity ticket. The identity ticket containins the following information:

- Name length (2 bytes): The length of the user's name in bytes.
- Name (n <= 65535 bytes): The user's name.
- Public key (32 bytes): The user's public key.
- Challenge answer (64 bytes): The answer to a random challenge signed with the user's private key.
- Signature for preceding content (64 bytes): The signature of the preceding content (name length, name, public key, challenge answer) signed with the user's private key.
  
To verify the identity ticket, the recipient compares the ticket's signature and challenge answer against the ticket's public key to determine if the ticket is valid.

The Slim protocol is designed to be simple and easy to use, with keys derived from user credentials that are easy to store and even remember by humans. It is designed for applications that require peer-to-peer identity management without a central authority.

## Documentation

### slimprotoVersion

Returns the version of the protocol that is implemented.

### createKeyPair(name, password)

Generates an Ed25519 key pair for the given name and password. The key pair is returned as a buffer containing the concatenated private key (32 bytes) and public key (32 bytes), totaling 64 bytes.

Parameters:
<dl>
  <dt>name</dt>
  <dd>User's name.</dd>
  <dt>password</dt>
  <dd>User's password.</dd>
</dl>

Returns:

Buffer containing concatenated private key (32 bytes) and public key (32 bytes), total 64 bytes.

### keyPairToObject(keyPair)

Converts a buffer containing concatenated public and private keys (generated with `createKeyPair`) into an object with separate `publicKey` and `privateKey` properties.

### createIdentityTicket(name, password, challenge)

Generates a Slim identity ticket for a given name, password, and challenge. The ticket is returned as a buffer containing the following information:

- Name length (2 bytes): The length of the user's name in bytes.
- Name (n <= 65535 bytes): The user's name.
- Public key (32 bytes): The user's public key.
- Challenge answer (64 bytes): The answer to the challenge signed with the user's private key.
- Signature for preceding content (64 bytes): The signature of the preceding content (name length, name, public key, challenge answer) signed with the user's private key.

Parameters:
<dl>
  <dt>name</dt>
  <dd>User's name.</dd>
  <dt>password</dt>
  <dd>User's password.</dd>
  <dt>challenge</dt>
  <dd>A buffer of random bytes to be signed.</dd>
</dl>

Returns:

Identity ticket, a concatenated buffer containing specified information.

### ticketToObject

Converts a buffer ticket with concatenated data to an object with a appropriate properties: `nameLength`, `name`, `publicKey`, `challengeAnswer`, `signature`.

### verifyIdentityTicket(ticket, challengeQuestion)

Verifies a given identity ticket by comparing the ticket's signature and challenge answer against the ticket's public key.

Parameters:
<dl>
  <dt>ticket</dt>
  <dd>A Slim ticket.</dd>
  <dt>challengeQuestion</dt>
  <dd>The original Buffer of data sent to and signed by the ticket issuer.</dd>
</dl>

Returns:

`true` if the ticket is valid, `false` if not.

### solveChallenge(challenge, privateKey)

Solves a given challenge by signing it with the private key.

Parameters:
<dl>
  <dt>challenge</dt>
  <dd>A Buffer provided as the challenge.</dd>
  <dt>privateKey</dt>
  <dd>The user's private key.</dd>
</dl>

Returns:

Base64 string answer.

### generateRandomChallenge(*[length]*)

Generates `length` bytes of random data to be used as a challenge. `length` is optional and default is `512`.

## Testing

A simple testing script is included. It generates a test ticket and verifies it. A successful test should end with the final ticket verification returning `true`. Run with `npm test`.

## Example usage

User A:
```js
// User A wishes to verify the identity of User B.
// User A creates a challenge.
const challenge = generateRandomChallenge()

//
// This challenge is then sent to User B.
//
```

User B:
```js
// User B creates an identity ticket with their credentials and the provided challenge.
const ticketB = createIdentityTicket('UserB', 'Wordpass', challenge)
// => <Buffer 05 00 55 73 65 72 42 59 d7 66 d9 19 cb 8f 74 43 59 d3 45 36 b9 0f d5 2a 68 64 4a 13 4e 94 e0 73 8e b7 30 34 04 14 27 7f 06 6b 40 88 da 93 dd 1b 28 c2 ... 117 more bytes>

//
// This ticket is then sent to User A.
//
```

User A :
```js
// User A verifies the ticket.
verifyIdentityTicket(ticketB, challenge)
// => true
// User A now agrees User B is who they claim to be, "UserB" with the public key <Buffer 59 d7 66 d9 19 cb 8f 74 43 59 d3 45 36 b9 0f d5 2a 68 64 4a 13 4e 94 e0 73 8e b7 30 34 04 14 27>
```