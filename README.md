# slimproto-core

#### Peer-to-peer identity management protocol.

With Slim, peers can verify each other's identities without a central identity authority. A user creates an _identity ticket_ with a public name and a private password. From these an Ed25519 key pair is generated, which is used to identify the user.

---

# Usage

## createKeyPair(name, password)

Creates an Ed25519 key pair for a given name and password.

Parameters:
<dl>
  <dt>name</dt>
  <dd>User's name.</dd>
  <dt>password</dt>
  <dd>User's password.</dd>
</dl>

Returns:

```js
{ privateKey, publicKey }
```

## createIdentityTicket(name, password, challenge)

Creates a Slim identity ticket for a given name and password, identifying this user. A challenge consisting of a sequence of random bytes is provided by the other party and signed with this user's private key. The entire ticket is then signed as well.

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

```js
ticket = {
    name,
    publicKey,
    challengeAnswer,
    signature
  }
```

## verifyIdentityTicket(ticket, challengeQuestion)

Verifies a given Slim identity ticket by comparing the ticket's signature and challenge answer against the ticket's public key.

Parameters:
<dl>
  <dt>ticket</dt>
  <dd>A Slim ticket.</dd>
  <dt>challengeQuestion</dt>
  <dd>The original Buffer of data sent to and signed by the ticket issuer.</dd>
</dl>

Returns:

`true` if the ticket is valid, `false` if not.

## solveChallenge(challenge, privateKey)

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

---

```js
// User A wishes to verify the identity of User B.
// User A creates a challenge.
const challenge = Buffer.from([1, 2, 3, 4])

//
// This challenge is then sent to User B.
//

// User B creates an identity ticket with their credentials and the provided challenge.
const ticketB = createIdentityTicket('UserB', 'Wordpass', challenge)
// => { name: 'UserB', publicKey: 'jAlpP1nEJ+/y6A6D...

//
// This ticket is then sent to User A.
//

// User A verifies the ticket.
verifyIdentityTicket(ticketB, challenge)
// => true
// User A now agrees User B is who they claim to be, "UserB" with the public key "jAlpP1nEJ+/y6A6D..."
```