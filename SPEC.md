# aza identity

This document specifies how accounts work across aza: one account that signs in to every aza app and to apps built by anyone else, without an accounts server. It describes only what is decided.

## 1. Goals

- **One account everywhere.** The same account signs in to aza's own apps and to apps anyone else builds.
- **No accounts server.** No company, including aza, can create, lock or delete an account that its owner controls. The protocol has no email, phone number or password reset; providers may offer email sign-up on top of it, and people can take control later (section 8.2).
- **No big-platform dependency.** Accounts don't depend on Apple, Google or a cryptocurrency wallet.
- **Lost is lost.** If you control your own keys and lose them all, the account is gone. There is no recovery service, so there is nobody to trick into taking over your account.
- **Offline first.** Apps work fully without the network. Syncing data through aza is optional.
- **Anyone can run the infrastructure.** Servers that store accounts can be run by anyone, and aza's own server has no special powers.

## 2. The parts at a glance

Each of these is specified in detail later; this is just enough to read the rest in order.

- An **identity** is one account: a person, a bot or an organisation.
- An identity is stored as a **change log**: a list of signed **changes** (adding a device, setting the profile and so on) that anyone can read to learn its current state.
- A **device** is a key that controls an identity. It lives in the aza app on a phone or computer, or in a password-protected backup file.
- The **master** is one special device per identity. It can't be signed out or removed, it alone can remove other devices for good, and it can hand its role to a new key that it committed to in advance.
- The **aza app** is aza's own app that holds devices and approves sign-ins.
- A **node** is a server that stores identities and app data. Anyone can run one.
- An identity's **home node** is the node it has chosen to store its data.
- An **app** is any service people sign in to with an aza identity, such as Heavier or someone's video game.
- A **client** is one program acting for an identity inside an app, like the iPhone version of a messenger. Clients get limited permission from a device and never hold a device key.
- **Sync data** is an app's data, encrypted and stored on a node so its clients can share it.
- **Public records** are an app's data that anyone can read, signed so it provably comes from the identity, such as posts.
- An identity's **inbox** is where others leave sealed messages for its devices and clients.
- **Proof of work** is a computing cost paid once when an identity is created, to make mass-creating identities expensive.

## 3. Cryptography and encoding

**Signing key pair.** A private key and a public key. The private key signs data; the public key lets anyone check those signatures. aza uses a *hybrid* key pair: an [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) key pair plus an [ML-DSA-65](https://en.wikipedia.org/wiki/ML-DSA) key pair, used together. ML-DSA is designed to survive [quantum computers](https://en.wikipedia.org/wiki/Post-quantum_cryptography); Ed25519 is older and well understood. Using both means an attacker has to break both. A hybrid public key is the Ed25519 public key followed by the ML-DSA-65 public key: 32 + 1952 = 1984 bytes.

**Signature.** The same message signed with both private keys: the Ed25519 signature followed by the ML-DSA-65 signature, 64 + 3309 = 3373 bytes. It is valid only if both halves check out.

**Encryption key pair.** An X-Wing key pair, as defined in [draft-connolly-cfrg-xwing-kem-11](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html): X25519 and ML-KEM-768 combined into one, so breaking it means breaking both. Its public key is 1216 bytes. Anyone can use it to encrypt data that only the private key's holder can read.

**Hash.** [SHA-256](https://en.wikipedia.org/wiki/SHA-2): 32 bytes.

**Fingerprint.** The hash of a public key. It's a short way to name a key: 32 bytes instead of 1984.

**HKDF.** [HKDF-SHA256](https://en.wikipedia.org/wiki/HKDF), a standard way to turn one secret into other secrets, each tied to a label (its `info`), so that knowing one derived secret reveals nothing about the others. aza always uses an empty salt and a 32-byte output.

**Symmetric encryption.** [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) with a random 12-byte **nonce** (a value used once per encryption). It also detects any tampering with the encrypted data.

**Sealing.** Encrypting data so that only the holder of one encryption key pair can read it. aza uses [HPKE](https://www.rfc-editor.org/rfc/rfc9180) (RFC 9180) in its base mode with X-Wing, HKDF-SHA256 and AES-256-GCM, and `info` = `"aza seal v1"`. A **sealed box** is HPKE's 1120-byte encapsulated key followed by the encrypted data.

**Encoding.** Everything is encoded as [CBOR](https://en.wikipedia.org/wiki/CBOR) using the deterministic encoding of RFC 8949 section 4.2.1, which gives every value exactly one byte form. A signature covers the encoded object without its `sig` field; a hash covers the whole encoded object. A fingerprint is the hash of a public key's bytes as laid out above. Keys, signatures and hashes are CBOR byte strings. Examples in this document are written as JSON, with byte strings shortened to hex like `"9f2c…"`.

## 4. Devices and the master

A **device** is a signing key pair plus an encryption key pair that together control an identity. Its private keys are stored in the **aza app** on a phone or computer (only on that machine, never synced to any cloud) or in a **backup file** (section 8).

The **aza app** is aza's standalone app for iPhone, Mac and other platforms. It is the only program that ever handles device keys. Its jobs are creating identities, adding devices and approving sign-ins.

The **master** is one device that is never a phone's or computer's everyday key. When an identity is created, the aza app makes the master and a device for that phone or computer. Moving the master into a backup file changes nothing in the identity: it's the same key, kept somewhere else.

The master's job is repair. It can't be signed out or removed, and only it can remove a device for good (section 5.4).

**Pre-rotation.** Every master commits in advance to the key that may hand its role on. Its change (the genesis change, or the `set-master` change that made it master; section 5.3) carries `next`: the fingerprint of a **next key** that is made at the same time but kept secret. Only that next key can **hand off** the role (section 5.4 makes the rules exact), by signing a `set-master` change that reveals it and brings in a fresh master key and a fresh next key. A next key is used exactly once and then destroyed, and a master key is never anyone's next key. So the master is really two keys kept apart: the **current master key**, used for repairs, and the **next key**, used only for a handoff. The aza app saves them into two separate backup files, each with its own password, and strongly recommends keeping those in different places, then deleting both from the machine.

- **If the current master key is stolen**, the thief can make repairs but can't hand off the role. The person hands off with the next key. The aza app builds the handoff's `prev` (section 5.1) only from changes that have nothing the thief signed among their ancestors, so everything the thief signed with the stolen key stops counting (master changes, section 5.4). Because ancestry carries through, changes made after the theft are left out too and have to be made again. The aza app then replaces the data secret (section 9), because the thief could read the old one.
- **If a next key leaks**, with or without the current key, whoever has it can hand off the role to themselves. The person's only answer is a competing handoff, and competing handoffs cancel each other and leave the identity without a master for good (section 5.4). Either way the identity has to be abandoned.

Every device other than the master is an **ordinary device**. Every device can add devices, sign out ordinary devices other than itself, change the profile and revoke clients. **Signing out** stops a device straight away, for example a phone that was just stolen. **Removing**, which only the master can do, is final and replaces any sign-outs of that device: the master decides what of the device's history to keep.

A device is **current** from when it is added until it is signed out or removed (section 5.4 makes this exact). An identity can have at most 64 ordinary devices that haven't been removed; signed-out devices count until the master removes them. A machine whose device was removed makes new key pairs before it is added again.

## 5. Identity

An identity is stored as a **change log**: a list of **changes**, each signed by one of its devices. Reading the log tells you everything about the identity: its devices, its master, its profile and so on.

### 5.1 Changes

Every change has the same fields:

```json
{
  "v": 1,
  "identity": "9f2c…",
  "prev": ["41d0…"],
  "time": 1793500000,
  "by": "c87a…",
  "body": { "type": "add-device", "key": "…", "enc": "…", "label": "MacBook" },
  "sig": "…"
}
```

| Field | Meaning |
|---|---|
| `v` | Protocol version the change follows (section 13). |
| `identity` | The identity ID (section 5.2). Absent in the genesis change. |
| `prev` | Hashes of the newest changes the signing device knew about when it signed. Absent in the genesis change. Usually one hash; more than one when the device had seen two changes made at the same time. The signer chooses `prev` and nobody can check it was honest; section 5.4 says what a dishonest `prev` can and can't do. |
| `time` | Unix seconds, as claimed by the signer. Shown to people, never used to decide anything. |
| `by` | Device ID (section 5.2) of the device that signed. Absent in `genesis` and `set-master` changes. |
| `body` | What the change does (section 5.3). |
| `sig` | Signature over all the other fields: by device `by`, or by `body.key` in a `genesis` change and by `body.reveal` in a `set-master` change. |

The **ancestors** of a change are the changes listed in its `prev`, the changes listed in their `prev`, and so on back to the start. A change only counts as an ancestor if it is actually in the log.

### 5.2 The genesis change, the identity ID and device IDs

The **genesis change** is the first change of every identity. Its body holds the first master's public keys, its `next`, the proof of work (section 12) and the `check` of the first data secret (section 9). It is signed by that master.

The **identity ID** is the hash of the genesis change. It never changes. Everything that refers to an identity uses its identity ID.

A **device ID** names one device: the hash of the change that brought it in. For an ordinary device that is its `add-device` change; for the first master it is the genesis change (so its device ID is the identity ID); for a later master it is the `set-master` change. Devices are named this way rather than by their key so that a removal applies to one specific addition, never to some other addition of the same key.

### 5.3 Change types

| `body.type` | Fields | Who may sign it | Effect |
|---|---|---|---|
| `genesis` | `key`, `enc`, `next`, `counter`, `check` | the master it creates | creates the identity. `next` is the fingerprint of the next key; `check` is for the first data secret (section 9). |
| `add-device` | `key`, `enc`, `label` | any device | adds an ordinary device. Not allowed if `key` has been used by any master or device or its fingerprint is any master's `next`, or if the identity would then have more than 64 ordinary devices that haven't been removed. |
| `sign-out` | `device` (device ID) | any device | signs out a current ordinary device other than the signer itself |
| `remove-device` | `device` (device ID), `keep` (change hash, optional) | the master only | removes an ordinary device for good. `device` must be the device ID of an `add-device` change among this change's ancestors. `keep`, if given, must be a change signed by `device` and an ancestor of this change. |
| `set-master` | `reveal`, `key`, `enc`, `next` | the next key named by the current master's `next`, revealed in `reveal` | hands the master role to the fresh keys `key` and `enc`, and commits to a new `next`. `key` must not be the key of any master or device among its ancestors. |
| `set-profile` | `name`, `picture`, `handle` | any device | replaces the profile (section 6) |
| `set-home` | `node` (URL) | any device | sets the home node (section 11) |
| `revoke-client` | `client` (fingerprint) | any device | revokes a client (section 7) |
| `new-secret` | `check` | the master only | announces a new data secret (section 9) |

`key` is a signing public key and `enc` an encryption public key.

### 5.4 Reading the log

Two devices can sign changes without knowing about each other. For example, aiden's phone is on a plane and adds a device while aiden's laptop updates the profile. Both changes list the same change in `prev`. Two changes are **concurrent** when neither is an ancestor of the other.

A log is read in five steps. Each step only uses the results of the steps before it.

**Step 1: the master.** The masters form a **master chain**, worked out on the whole log. Its first link is the genesis change. A `set-master` change is the **next link** after link L if the fingerprint of its `reveal` equals L's `next`, its signature is valid for `reveal`, L is one of its ancestors, its `key` isn't the `key` of any `genesis`, `set-master` or `add-device` change among its ancestors, and the fingerprint of its `key` isn't its own `next`. The genesis change likewise needs the fingerprint of its `key` to differ from its `next`. A link's **master key** is its `key`. If a link has exactly one next link, the chain continues from there. If it has two or more, that is a **master conflict**: the chain ends at that link, none of its next links count, and the identity has no master from then on.

A **master change** is a link itself, or a change whose `by` is a link's device ID, signed by that link's master key, that has that link among its ancestors and is an ancestor of every next link of that link. In other words, a master's changes only count if they were made while it was the master: a former master's changes made after (or concurrently with) its handoff don't count, however `prev` was faked. If the chain ended in a master conflict, only that last link's master changes that are ancestors of all the conflicting next links count. The aza app signs exactly one handoff per next key and re-uploads that same change if it needs to, because two different handoffs by the same next key are a master conflict.

**Step 2: master removals.** A `remove-device` change is a **master removal** if it is a master change (step 1) and follows the rules in section 5.3. If the master removes the same device more than once, a change by that device survives only if it is the `keep`, or an ancestor of the `keep`, of every one of those removals (one without `keep` discards everything).

**Step 3: discarded changes.** A change signed by a link's master key that isn't a master change (step 1) is **discarded**. A change signed by ordinary device D is **discarded** if:

- there is a master removal of D, and the change is neither that removal's `keep` nor an ancestor of it; or
- the `add-device` change that added D is itself discarded.

Discarded changes are ignored from here on. In other words, the master removal draws a line through the removed device's history: everything up to `keep` stays, and everything after it is gone, including any devices it added after that point and everything they signed.

**Step 4: sign-outs and revocations.** Two kinds of change are **judged on their own**: read a log made of only the change's ancestors (by all five steps), then check the change against rules 1 to 3 of step 5 at the end of that reading. Whether a change is discarded, and whether it is a master change, is always decided on the whole log, for the change being judged and for every change in the reading of its ancestors: a sign-out or revocation signed by a master's keys only counts if it is a master change of the whole log (step 1).

- A **sign-out** of device D is a `sign-out` change for D that isn't discarded, is allowed when judged on its own, and D has no master removal. (Once the master removes D, the removal's `keep` alone decides what of D survives.)
- A **revocation** is a `revoke-client` change that isn't discarded and is allowed when judged on its own.

Judging on their own means two devices that sign each other out at the same moment are both signed out, rather than whoever happens to come first winning.

**Step 5: applying changes.** Go through the changes that aren't discarded in **reading order**: repeatedly take, out of the changes not yet taken whose ancestors (other than discarded ones) have all been taken, the one with the smallest hash. That puts every change after its ancestors and gives everyone the same order. A device is **current** at a given point if it was added by a change already applied, and no sign-out or master removal of it has been reached yet. The master of the last link (if the chain didn't end in a master conflict) also counts as current everywhere; masters of earlier links are never current at the end of the log. Links are applied as step 1 decides, without rules 1 to 3, and `set-master` changes that aren't links are ignored. Master removals, sign-outs and revocations take effect when they are reached. Any other change is applied if all of these hold:

1. its signature is valid for the key of device `by`;
2. it is a master change, or `by` is a current ordinary device at this point;
3. its body follows the rules in section 5.3;
4. it is an ancestor of every sign-out of `by`.

When several changes set the same thing, such as two `set-profile`s, the last one applied wins.

**What this means in practice.**

- When a device is signed out, everything it signed that the device signing it out hadn't already seen is ignored (rule 4), including devices it added and everything those devices signed. The exception is sign-outs and revocations by it, or by devices it added: those are judged on their own, so they count until the master acts.
- `prev` can't be checked, so a stolen device can fake it to make a sign-out or revocation look old. Until the master acts, a stolen device can therefore sign out any other ordinary device and revoke any client, and a device signed out like that has its work put on hold by rule 4.
- The master repairs all of it. The aza app shows the stolen device's changes, the person picks the last one they trust as `keep`, and the master removes the device. Everything the stolen device signed after `keep` is discarded, including its sign-outs and revocations and every device it added after `keep`. The devices and clients it attacked come back with their work, and its changes up to `keep` count even if someone signed it out without having seen them.
- A master removal is final, unless the master's next handoff leaves it out of its ancestors; the aza app includes every master change in a handoff's `prev` except ones the person disowns after a theft. If the master removes an honest device by mistake, that machine makes new keys and is added again.
- Additions that come back after a repair count toward the 64-device limit from their original place in reading order. So if the identity was at the limit, a later addition can fail; the aza app warns before signing a removal that would cause this.
- No ordinary device ever holds the master's keys, so stealing a phone or computer never gives the thief the master.
- After a master conflict nothing can remove devices any more, and the identity has to be abandoned.

**Example: a stolen phone.** A thief steals aiden's unlocked phone and adds the thief's own device. aiden's laptop, not having seen that, signs out the phone. The thief's `add-device` isn't an ancestor of that sign-out, so rule 4 ignores it, and the thief's device never becomes current. Its sign-outs and revocations still count for now, and so do the phone's: the thief uses the phone to sign out the laptop, faking `prev` so it looks older, and now both are signed out. aiden opens the master's backup file in the aza app and removes the phone with `keep` set to the phone's last change before the theft. The thief's sign-out of the laptop and everything the thief's device did are discarded, the laptop is current again, and everything it did since counts.

The aza app downloads the newest log from the home node before signing any change, so that it doesn't throw away legitimate changes it simply hadn't seen yet.

## 6. Profile

The **profile** is what other people see. It has three fields, all set by `set-profile`:

- **`name`**: the display name. Any text up to 64 characters. Not unique: anyone can be "aiden".
- **`picture`**: an `https` URL of an image, up to 2048 characters.
- **`handle`**: optional. A domain the identity owns.

A **handle** is a [registrable domain](https://en.wikipedia.org/wiki/Public_Suffix_List): the part of a domain you can buy, like `sidny.me` or `example.com.au`, but never a subdomain like `blog.sidny.me`. To prove it, the owner adds this DNS record, with the identity ID written as 64 lowercase hex characters:

```
_aza.sidny.me  TXT  "aza=<identity ID> node=<home node URL>"
```

An app shows a handle only after looking up that record through a public [DNS-over-HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS) resolver and finding the identity's ID in it. Otherwise it shows the display name only. The `node=` part lets someone who only knows the handle find the change log. When the identity moves to another home node, the aza app reminds the owner to update the record.

## 7. Apps, clients and certificates

An **app** is a service, named by a domain it controls: `heavier.aza.network`, `coolgame.com`. That domain is its **app ID**. The aza app's own app ID is `aza.network`.

A **client** is one piece of software acting for an identity inside one app. The iPhone and Mac versions of a messenger are two clients of one app. Each client makes its own signing key pair, the **client key**, and, if it will read sync data, its own encryption key pair. Clients never see device keys.

A client gets permission through a **certificate**: a statement signed by a device, which the client keeps. It is not published in the change log, so the log doesn't reveal which apps an identity uses. The home node does see certificates, and public records and key packages show their apps to anyone (section 10).

```json
{
  "identity": "9f2c…",
  "node": "https://node.example",
  "app": "coolgame.com",
  "client": "<client signing public key>",
  "enc": "<client encryption public key, only with the read or receive scope>",
  "scopes": ["sign-in"],
  "time": 1793500000,
  "by": "c87a…",
  "sig": "…"
}
```

`by` is the device ID of the device that signed. `node` is the identity's home node when the certificate was signed: a starting point for finding the change log.

**Scopes** say what the client may do:

| Scope | Allows |
|---|---|
| `sign-in` | proving it acts for the identity in this app |
| `read` | reading this identity's sync data for this app (section 9) |
| `write` | storing sync data for this app. A certificate with `write` must also have `read`, because a client needs the app key to encrypt. |
| `publish` | publishing public records for this app (section 10) |
| `receive` | publishing key packages and reading inbox items for this app (section 10). Needs the client's encryption key. |

**Getting a certificate.** The client makes a **request** holding its app ID, client key, encryption key (if asking for `read` or `receive`), the scopes it wants, and a **return URL**. The return URL must be an `https` URL whose host is exactly the app ID. The aza app refuses any request whose return URL isn't, because the return URL is how the aza app knows the certificate can only reach the real app:

- **On the same machine**, the client opens the aza app with the request. After approval, the aza app opens the return URL with the certificate attached. For a website, that loads the app's own site. For an iPhone, Mac or other native app, the return URL must be a verified app link (a [universal link](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app) on Apple platforms): the operating system only opens it in an app the domain itself lists, so a fake app never receives it.
- **From another machine**, the client shows the request as a QR code, which the aza app scans. After approval, the aza app sends the certificate to the return URL with an HTTPS `POST`. The app's own server then hands it to the client that asked.

Verified app links exist on Apple platforms and Android; on platforms without them, native apps use the other-machine path. A host of exactly the app ID means `www.coolgame.com` is a different app from `coolgame.com`. The other-machine path still has one weakness: a phishing site can show the real app's QR code, relayed live, and receive the certificate the app's server hands out. The aza app always shows the app ID it is approving, so the person can see that it's `coolgame.com` and not the site they're on.

**Checking a certificate.** Anyone, such as a game's server, gets the change log starting from the certificate's `node` (and then from the home node named by the log's latest `set-home`, if different), and accepts the certificate only if:

1. its signature is valid;
2. device `by` is current at the end of the log (not signed out or removed);
3. the log has no revocation of this client key's fingerprint;
4. its `app` is the app doing the checking;
5. the client proves it holds the client key, by signing a fresh random challenge from the checker. A copied certificate is useless without the client's private key.

A certificate stops working when the device that signed it is signed out or removed; the aza app on another device can then approve the client again with one tap. A node can't forge changes, but it can hide the newest ones, so a checker that only sees an out-of-date log may accept a certificate whose device has since been signed out or removed, until it sees the newer log.

A client is **current** for an app while it holds a certificate for that app that passes checks 1 to 3.

**Revoking.** A `revoke-client` change puts only the client key's fingerprint into the log, so it doesn't reveal which app the client belonged to.

**The list of approvals.** The aza app keeps at most 64 certificates in effect per identity. It stores the list of them as its own sync data (section 9), so every device of the identity shows the same apps, clients and scopes, and any of them can revoke one.

## 8. Keeping the master

### 8.1 Backup files

A **backup file** holds a device's private keys, or a master's next key, encrypted with a password. It is how the master is meant to be kept, but any device can be saved this way.

```json
{
  "format": 1,
  "argon2id": { "salt": "…", "memory": 65536, "iterations": 3, "parallelism": 1 },
  "nonce": "…",
  "ciphertext": "…"
}
```

The password is turned into a 256-bit key with [Argon2id](https://en.wikipedia.org/wiki/Argon2), a deliberately slow and memory-hungry function that makes guessing passwords expensive. `salt`, `memory` (in KiB; 65536 KiB is 64 MiB), `iterations` and `parallelism` are its settings, chosen when the file is made. That key encrypts the contents with AES-256-GCM. The encrypted contents are:

- the identity ID,
- the device's private signing and encryption keys (or, for a next key, its private signing key),
- the home node URL.

A password is required. Only the aza app opens backup files. To use one, you open it in the aza app on a phone or computer; the aza app uses the keys for that session only, for example to add the machine as a new device, and then forgets them.

### 8.2 Hosted masters

Backup files are a lot to ask of most people. A **provider**, which can be any node operator, may hold the master for someone instead: both its current master key and its next key. The person signs up with an email address, or any other login the provider offers; that login is between them and the provider and never appears in the protocol. Their phones and computers are ordinary devices. When they log in on a new phone, the provider uses the master to add it.

To the protocol a hosted master is an ordinary master, so nothing in the log shows that an identity is hosted. The provider also gets the master's envelope of the data secret (section 9), so it can read the identity's private data and restore it if every device is lost. The provider can do anything a master can, so a hosted identity is only as safe as its provider.

**Taking control.** Whenever the person wants, the aza app makes new master keys and a next key for them and asks the provider to hand off: the provider signs one `set-master` that reveals its next key and brings in the person's new master key, with `next` set to the fingerprint of the person's next key. Before accepting the handoff, the aza app checks that its `key` and `next` are the ones it sent and that every master change is among its ancestors, so the provider can't quietly undo earlier repairs; otherwise it refuses. It then lists every current device, and the new master removes any the person doesn't recognise, for example one the provider added, before the data secret is replaced. The identity ID never changes, so handle, followers and conversations carry over, and so do app approvals signed by the person's devices. Approvals the provider's master had signed stop working; the aza app lists them, and the person chooses which to approve again. The provider's master stops being current, and the aza app replaces the data secret (section 9), so the provider can't read anything written afterwards. A provider that secretly kept its old next key could still sign a competing handoff and leave the identity without a master (section 5.4), but it can never take the identity back.

## 9. Private data

Sync data is encrypted so that only the identity's devices and the clients it allowed to `read` can see it.

**Data secret.** Each identity has one **data secret**: 32 random bytes. The first one is made with the identity and each later one is announced by a `new-secret` change. Both the genesis change and each `new-secret` change carry a `check`: HKDF over that secret with `info` = `"aza secret check v1"`. The **current secret** is the one announced by the last `new-secret` change applied in reading order (or the first one, if there is none). A secret is named by the hash of its `new-secret` change, or by the identity ID for the first one. Each app's **app key** is HKDF over the data secret with `info` = `"aza app key v1"` followed by the app ID. An app key unlocks that app's sync data and nothing else.

**Envelopes.** The home node stores **envelopes**: a secret sealed (section 3) to one holder's encryption key, signed by the device that made it.

```json
{
  "identity": "9f2c…",
  "secret": "<name of the data secret>",
  "holder": "<device ID or client key fingerprint>",
  "sealed": "…",
  "by": "c87a…",
  "sig": "…"
}
```

The aza app writes an envelope of the data secret for each current device, including the master, and an envelope of the app key for each client whose certificate has `read`. A reader only uses an envelope signed by a device that is current at the end of the log, and checks the opened secret against its `check`. So a node or a signed-out device can't slip in a secret of its own. When a device stops being current, including a master after a handoff, the aza app makes new envelopes, from secrets it holds itself, to replace every envelope that device had signed, and only for secrets announced by applied changes. Readers may open envelopes for any secret announced by a `new-secret` change that was applied (section 5.4), so items not yet moved to the current secret stay readable. A new device or client gets its envelope from the home node and opens it with its own private encryption key. The backup file doesn't need the data secret, because the master's envelope is on the home node.

**Sync data.** Each item is encrypted with its app's key using AES-256-GCM:

```json
{
  "identity": "9f2c…",
  "app": "heavier.aza.network",
  "name": "workouts/2026-11-01",
  "version": 3,
  "secret": "<name of the data secret>",
  "nonce": "…",
  "ciphertext": "…"
}
```

`name` is the app's own name for the item. `version` starts at 1 and each write must be exactly one more than the stored version, so two clients writing at once can't both succeed: the second fetches, merges and tries again. `secret` names the data secret whose app key encrypted it. Everything except `nonce` and `ciphertext` is passed to AES-256-GCM as associated data, so a node can't move a ciphertext to another item or version without it being detected.

**Replacing the data secret.** A device that has been signed out or removed, and a client whose `read` access was revoked, still know the secret or app key they were given. Only the master replaces the data secret, so a stolen device can never plant one it knows. Right after a sign-out or a revocation of a `read` client, the aza app urges the person to open the master's backup file to do it, and does it automatically whenever the master removes a device. To replace it, the aza app makes a new data secret, signs a `new-secret` change, writes new envelopes for every current device and every `read` client, and re-encrypts all of the identity's sync data under the new app keys. A node refuses writes under any secret other than the current one, so a client that hasn't caught up gets an error, fetches its new envelope and tries again. Any device that finds an item still under an older secret, for example because re-encryption was interrupted, re-encrypts it. If a secret was announced by a change that later stopped counting, such as one a thief signed with a stolen master key, the aza app may still open it with an envelope it opened before, but only to re-encrypt that data under the current secret.

## 10. Public records and messages

These two pieces let apps such as social networks and messengers build on aza identities. Feeds, search, group chats and message formats belong to those apps' own specs; this section only covers what every app needs from the identity layer.

**Public records.** A **public record** is a piece of an app's data that anyone can read, such as a post:

```json
{
  "identity": "9f2c…",
  "app": "plarza.com",
  "name": "posts/2026-11-01-a",
  "version": 1,
  "content": "<app-defined CBOR>",
  "certificate": { "…": "the client's certificate (section 7)" },
  "sig": "…"
}
```

It is signed by a client key and carries that client's certificate; devices don't publish records themselves. Anyone accepts it if the signature is valid for the certificate's client key, the certificate's signature is valid, its signing device is current, its client isn't revoked, its `app` equals the record's `app`, and its scopes include `publish`. Because the certificate travels with the record, publishing reveals that the identity uses that app; that's the point of publishing. A record is valid only while its certificate is. Signing out a device therefore hides every record published through clients it approved, until the app re-publishes them, each with the next `version`, through a client whose certificate works. `name` and `version` follow the same rules as sync data (section 9). Public records are stored on the home node, and a `publish` client can delete them.

**Inbox.** Anyone can leave an **inbox item** for one of an identity's devices or `receive` clients:

```json
{
  "to": "<device ID or client key fingerprint>",
  "app": "chat.example",
  "sealed": "…"
}
```

`sealed` is sealed (section 3) to the holder's encryption key: a device's from the log, a client's from its certificate. What's inside is up to the app, and the node doesn't know who sent an item. A node only accepts items whose `to` is a current device or a client whose `receive` certificate for that `app` it holds; a `receive` client therefore stores its certificate on the home node. Senders learn a client's fingerprint and encryption key from its key package. Each node sets its own limits on inboxes, and may demand proof of work for each item, as for new identities (section 12).

**Key packages.** A messenger client with `receive` publishes [MLS](https://www.rfc-editor.org/rfc/rfc9420) **key packages** (RFC 9420) on the home node: small signed bundles that let other people add it to an encrypted group while it's offline. Each key package's credential is the client's certificate, so anyone adding the client can check it belongs to the identity. Anyone can ask for key packages, so anyone can find out whether an identity uses a given messaging app. Key packages are single-use, so the node hands each one out only once, and a client keeps several published.

## 11. Nodes

A **node** is a server that stores change logs, sync data, envelopes, certificates, public records, inbox items and key packages. Anyone can run one. Each node's operator decides what it stores, and may refuse any upload. aza runs a node too, and in the protocol it is like any other.

An identity's **home node** is the node it chose, with a `set-home` change, to hold its change log, sync data and envelopes. During setup the aza app suggests aza's node; any node works. The aza node stores up to 1 MB of sync data, envelopes and public records per identity; other nodes set their own limits. The aza node never counts the change log toward that limit, so an identity can always upload a sign-out or removal, however full its storage is.

**Moving.** Before signing a `set-home` for a new node, the aza app copies the change log, sync data, envelopes, certificates, public records, inbox items and key packages there. After the log gains that `set-home`, the old node keeps answering requests for the log for at least one year. Anyone who still has the old address, including clients whose certificate names the old node, sees the latest `set-home` and follows it.

**Copies.** A node may also keep copies of other identities' change logs, for example of people its own identities interact with, so they can still be found after their old node disappears. Whether it does is up to its operator.

### 11.1 Node API

Every node answers these HTTP requests under `https://<node>/aza/v1/`. Request and response bodies are CBOR (`content-type: application/cbor`).

| Request | Who may make it | What it does |
|---|---|---|
| `GET log/{identity}` | anyone | returns every change the node holds for the identity |
| `POST log/{identity}` | anyone | uploads changes; the node keeps those with valid signatures that it chooses to store, and checks a new identity's work against its admission price (section 12) |
| `GET sync/{identity}/{app}?since={n}` | a current device, or a client with `read` for `app` | returns the items the node has stored or changed since its own counter `n`, plus the new counter |
| `PUT sync/{identity}/{app}/{name}` | a current device, or a client with `write` for `app` | stores one item; refused unless `version` is exactly one more than the stored one and `secret` is the current secret |
| `POST certificates/{identity}` | anyone | stores a certificate, so its client can then authenticate by fingerprint |
| `GET envelopes/{identity}/{holder}` | the holder | returns the envelopes for that device ID or client key fingerprint |
| `POST envelopes/{identity}` | a current device | stores envelopes; the node keeps every valid one, and readers choose as in section 9 |
| `GET records/{identity}/{app}?since={n}` | anyone | returns the public records stored or changed since the node's counter `n` |
| `PUT records/{identity}/{app}/{name}` | a client with `publish` for `app` | stores one public record signed by that same client, under the same version rule as sync data |
| `DELETE records/{identity}/{app}/{name}` | a client with `publish` for `app` | deletes a public record |
| `POST inbox/{identity}/{app}` | anyone | leaves an inbox item, if the node accepts it (section 10) |
| `GET inbox/{identity}/{app}/{holder}?since={n}` | the holder: a current device, or a client with `receive` for `app` | returns its inbox items for `app` since the node's counter `n` |
| `DELETE inbox/{identity}/{app}/{holder}/{item}` | the holder | deletes an inbox item it has handled |
| `POST keypackages/{identity}/{app}` | a client with `receive` for `app` | publishes key packages |
| `GET keypackages/{identity}/{app}` | anyone | hands out one unused key package for each current `receive` client of `app`, removing it from the node |
| `GET picture?url={url}` | a current device or client of an identity whose home node this is | optional: fetches a profile picture on the identity's behalf, so the image's host never learns who is looking at whom |

Requests that need permission carry an `aza-auth` header: the base64url encoding of a CBOR object with the identity ID, `by` (a device ID, or a client key fingerprint whose certificate the node already holds), `time` (Unix seconds), a random 16-byte `nonce` and `sig`. `sig` is `by`'s signature over the CBOR array `[host, method, path with query, time, nonce, hash of the body]`. The header is about 4.6 KB. The node accepts it only if `host` is its own, `time` is within 5 minutes of its clock, it hasn't seen this `nonce` in that time, and `by` has permission after reading the newest log it holds:

- a device: it is current;
- a client: at least one certificate the node holds for that client key passes all of these: its `identity` and `app` match the path, its signing device is current, the client isn't revoked, and it has the scope the request needs.

## 12. Proof of work

Creating an identity costs computing time, so that nobody can cheaply create millions of identities and fill nodes with them.

The genesis change's `counter` is a number the creator picks. Run Argon2id over the genesis change (everything except `sig`), with 64 MiB of memory, 1 iteration, 1 lane, the salt `"aza work v1"` and a 32-byte output. The identity's **work** is how many zero bits that output starts with. The creator tries different counters until the work is high enough; each extra bit doubles the average number of tries. Checking takes a single run.

Argon2id is [memory-hard](https://en.wikipedia.org/wiki/Memory-hard_function): each run needs a large block of memory, which makes graphics cards and custom chips much less of an advantage over a phone.

The **minimum work** in version 1 is 6: about 2^6 = 64 tries, aimed at roughly 5 seconds on a 2022 iPhone. A genesis change below it is invalid. A node may also set its own, higher **admission price**: it refuses to store identities whose work is below it, for example during a spam attack. Work is fixed when the identity is created, so an identity created with little work can only use nodes that accept that amount. Later versions raise the minimum as hardware gets faster.

## 13. Versions

Every change has a version number `v`. Software that meets a field it doesn't know inside a change it otherwise understands ignores the field, so new optional fields don't break older software.

Software that meets a change type it doesn't know, or a higher `v` than it supports, checks whether it is discarded (section 5.4, step 3) and rules 1, 2 and 4 of step 5. If it isn't discarded and would pass them, the software treats the whole log as unreadable until it is updated, because skipping that change could give it a different list of devices from everyone else. If not, it ignores the change.

The spec lives in a public repository that anyone can fork. Each node and app chooses which spec it follows.

## 14. Walkthrough

aiden, whose domain is `sidny.me`:

1. **Create.** The aza app on aiden's iPhone makes the master's keys and finds a counter giving enough work. The master signs the genesis change, whose hash is aiden's identity ID. The master then signs `add-device` for the iPhone's own device, `set-profile` (name "aiden") and `set-home` (aza's node). The app makes the first data secret, seals envelopes of it for the master and the iPhone, and uploads the log and envelopes to aza's node.
2. **Back up.** The app saves the master's keys into one backup file and its next key into another, each protected by its own password, and deletes them from the iPhone. aiden keeps the two files in different places. Nothing in the log changes.
3. **Laptop.** The aza app on aiden's Mac makes the Mac's keys and shows a QR code holding its public keys. aiden scans it with the iPhone, which signs `add-device` for the Mac and seals an envelope of the data secret for it.
4. **Handle.** aiden adds `_aza.sidny.me TXT "aza=<identity ID> node=<aza node URL>"` and signs `set-profile` with `handle: "sidny.me"`. Apps now show `@sidny.me`.
5. **A game.** coolgame on the Mac asks to sign in with scope `sign-in` and a return URL on `coolgame.com`. The Mac's aza app shows the request, aiden approves, and the Mac signs a certificate and opens the return URL, which only the real coolgame can receive. coolgame's server fetches aiden's log, checks the certificate (section 7) and has the game sign a challenge. Nothing about coolgame appears in aiden's change log.
6. **Stolen phone.** The Mac downloads the newest log and signs `sign-out` for the iPhone. Anything the thief did with the phone that the Mac hadn't seen is ignored, except sign-outs and revocations (section 5.4), and certificates the iPhone signed stop working. To make it final, and to undo anything the thief did, such as signing out the Mac, aiden opens the master's backup file in the aza app and removes the iPhone with the master, keeping its changes up to the last one aiden trusts. The aza app then replaces the data secret, so the phone can't read anything written after that.
7. **Offline apps.** Heavier works with none of this. Turning on aza sync makes Heavier ask for a certificate with `read` and `write`. It gets its app key from its envelope on aiden's home node, then uploads encrypted workouts there.
8. **Plarza.** aiden signs in to Plarza with a certificate that has `sign-in` and `publish`. Each post is a public record on aiden's home node, and anyone can check it came from `@sidny.me`.
9. **A friend joins.** aiden's friend signs up to Plarza with their email. Plarza's provider creates an identity with a hosted master and adds the friend's phone as a device. A year later the friend taps "take control" in the aza app; the provider hands off, and the friend now holds their own master, with the same identity ID and the same followers.
10. **Messages.** A messenger on aiden's Mac gets a certificate with `receive` and publishes key packages. A friend's messenger fetches one, adds aiden's Mac to an MLS group, and leaves the invitation in aiden's inbox.
