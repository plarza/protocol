# aza identity

This document specifies how accounts work across aza: one account that signs in to every aza app and to apps built by anyone else, without an accounts server. It describes only what is decided.

## 1. Goals

- **One account everywhere.** The same account signs in to aza's own apps and to apps anyone else builds.
- **No accounts server.** No company, including aza, can create, lock or delete an account. There is no email, no phone number and no password reset.
- **No big-platform dependency.** Accounts don't depend on Apple, Google or a cryptocurrency wallet.
- **Lost is lost.** If you lose every key to your account, the account is gone. There is no recovery service, so there is nobody to trick into taking over your account.
- **Offline first.** Apps work fully without the network. Syncing data through aza is optional.
- **Anyone can run the infrastructure.** Servers that store accounts can be run by anyone, and aza's own server has no special powers.

## 2. The parts at a glance

Each of these is specified in detail later; this is just enough to read the rest in order.

- An **identity** is one account: a person, a bot or an organisation.
- An identity is stored as a **change log**: a list of signed **changes** (adding a device, setting the profile and so on) that anyone can read to learn its current state.
- A **device** is a key that controls an identity. It lives in the aza app on a phone or computer, or in a password-protected backup file.
- The **master** is one special device per identity. It can't be signed out or removed, it alone can remove other devices for good, and it can hand its role to a new key.
- The **aza app** is aza's own app that holds devices and approves sign-ins.
- A **node** is a server that stores identities and app data. Anyone can run one.
- An identity's **home node** is the node it has chosen to store its data.
- An **app** is any service people sign in to with an aza identity, such as Heavier or someone's video game.
- A **client** is one program acting for an identity inside an app, like the iPhone version of a messenger. Clients get limited permission from a device and never hold a device key.
- **Sync data** is an app's data, encrypted and stored on a node so its clients can share it.
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

The **master** is one device that is never a phone's or computer's everyday key. When an identity is created, the aza app makes two devices: the master and one for that phone or computer. It strongly recommends saving the master into a backup file and deleting it from the machine. Until then the master's private keys stay in the aza app on that machine, separate from the machine's own device. Moving the master into a backup file changes nothing in the identity: it's the same key, kept somewhere else.

The master's job is repair. It can't be signed out or removed, and only it can remove a device for good (section 5.4). The master can also **hand off** its role to brand-new keys with a `set-master` change, for example when moving to a new backup file or routinely replacing old keys. After a handoff, the old master's keys count for nothing new, and they should be destroyed.

A handoff can't rescue a master whose keys have leaked. If anyone ever gets a master's private keys, current or former (by stealing them or guessing a backup file's password), they can fake `prev` to sign a competing handoff. Competing handoffs cancel each other and leave the identity without a master for good (section 5.4). Either way, the identity has to be abandoned. That's why the master belongs in a backup file kept offline, and why old master keys should be destroyed after a handoff.

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
| `v` | Protocol version the change follows (section 12). |
| `identity` | The identity ID (section 5.2). Absent in the genesis change. |
| `prev` | Hashes of the newest changes the signing device knew about when it signed. Absent in the genesis change. Usually one hash; more than one when the device had seen two changes made at the same time. The signer chooses `prev` and nobody can check it was honest; section 5.4 says what a dishonest `prev` can and can't do. |
| `time` | Unix seconds, as claimed by the signer. Shown to people, never used to decide anything. |
| `by` | Device ID (section 5.2) of the device that signed. Absent in the genesis change, whose signature is checked against its own `body.key`. |
| `body` | What the change does (section 5.3). |
| `sig` | Signature by device `by` over all the other fields. |

The **ancestors** of a change are the changes listed in its `prev`, the changes listed in their `prev`, and so on back to the start. A change only counts as an ancestor if it is actually in the log.

### 5.2 The genesis change, the identity ID and device IDs

The **genesis change** is the first change of every identity. Its body holds the first master's public keys and the proof of work (section 11). It is signed by that master.

The **identity ID** is the hash of the genesis change. It never changes. Everything that refers to an identity uses its identity ID.

A **device ID** names one device: the hash of the change that brought it in. For an ordinary device that is its `add-device` change; for the first master it is the genesis change (so its device ID is the identity ID); for a later master it is the `set-master` change. Devices are named this way rather than by their key so that a removal applies to one specific addition, never to some other addition of the same key.

### 5.3 Change types

| `body.type` | Fields | Who may sign it | Effect |
|---|---|---|---|
| `genesis` | `key`, `enc`, `counter`, `check` | the master it creates | creates the identity; `check` is for the first data secret (section 9) |
| `add-device` | `key`, `enc`, `label` | any device | adds an ordinary device. Not allowed if `key` has been used by any master, or if the identity would then have more than 64 ordinary devices that haven't been removed. |
| `sign-out` | `device` (device ID) | any device | signs out a current ordinary device other than the signer itself |
| `remove-device` | `device` (device ID), `keep` (change hash, optional) | the master only | removes an ordinary device for good. `device` must be the device ID of an `add-device` change among this change's ancestors. `keep`, if given, must be a change signed by `device` and an ancestor of this change. |
| `set-master` | `key`, `enc` | the master only | hands the master role to these new keys. `key` must not have been used by any earlier master or device. |
| `set-profile` | `name`, `picture`, `handle` | any device | replaces the profile (section 6) |
| `set-home` | `node` (URL) | any device | sets the home node (section 10) |
| `revoke-client` | `client` (fingerprint) | any device | revokes a client (section 7) |
| `new-secret` | `check` | the master only | announces a new data secret (section 9) |

`key` is a signing public key and `enc` an encryption public key.

### 5.4 Reading the log

Two devices can sign changes without knowing about each other. For example, aiden's phone is on a plane and adds a device while aiden's laptop updates the profile. Both changes list the same change in `prev`. Two changes are **concurrent** when neither is an ancestor of the other.

A log is read in five steps. Each step only uses the results of the steps before it.

**Step 1: the master.** The masters form a **master chain**, worked out on the whole log. Its first link is the genesis change. A `set-master` change is the **next link** after link L if its `by` is L's device ID, its signature is valid for L's key, and L is one of its ancestors. If a link has exactly one next link, the chain continues from there. If it has two or more, that is a **master conflict**: the chain ends at that link, none of its next links count, and the identity has no master from then on.

A **master change** is a change whose `by` is some link's device ID, with a valid signature for that link's key, that has that link among its ancestors (or is the genesis change) and is an ancestor of every next link of that link. In other words, a master's changes only count if they were made while it was the master: a former master's changes made after (or concurrently with) its handoff don't count, however `prev` was faked. If the chain ended in a master conflict, only that last link's master changes that are ancestors of all the conflicting next links count.

**Step 2: master removals.** A `remove-device` change is a **master removal** if it is a master change (step 1) and follows the rules in section 5.3. If the master removes the same device more than once, a change by that device survives only if it is the `keep`, or an ancestor of the `keep`, of every one of those removals (one without `keep` discards everything).

**Step 3: discarded changes.** A change signed by ordinary device D is **discarded** if:

- there is a master removal of D, and the change is neither that removal's `keep` nor an ancestor of it; or
- the `add-device` change that added D is itself discarded.

Discarded changes are ignored from here on. In other words, the master removal draws a line through the removed device's history: everything up to `keep` stays, and everything after it is gone, including any devices it added after that point and everything they signed.

**Step 4: sign-outs and revocations.** Two kinds of change are **judged on their own**: read a log made of only the change's ancestors (by all five steps), then check the change against rules 1 to 3 of step 5 at the end of that reading. Whether a change is discarded is always decided on the whole log, by step 3, and so is whether it is a master change: a sign-out or revocation signed by a master's keys only counts if it is a master change of the whole log (step 1).

- A **sign-out** of device D is a `sign-out` change for D that isn't discarded, is allowed when judged on its own, and D has no master removal. (Once the master removes D, the removal's `keep` alone decides what of D survives.)
- A **revocation** is a `revoke-client` change that isn't discarded and is allowed when judged on its own.

Judging on their own means two devices that sign each other out at the same moment are both signed out, rather than whoever happens to come first winning.

**Step 5: applying changes.** Go through the changes that aren't discarded in **reading order**: repeatedly take, out of the changes not yet taken whose ancestors have all been taken, the one with the smallest hash. That puts every change after its ancestors and gives everyone the same order. A device is **current** at a given point if it was added by a change already applied, and no sign-out or master removal of it has been reached yet. The master at the end of the chain (if the chain didn't end in a master conflict) also counts as current everywhere, since it can never be signed out or removed. Master removals, sign-outs and revocations take effect when they are reached. Any other change is applied if all of these hold:

1. its signature is valid for the key of device `by`;
2. it is a master change, or `by` is a current ordinary device at this point;
3. its body follows the rules in section 5.3;
4. it is an ancestor of every sign-out of `by`.

When several changes set the same thing, such as two `set-profile`s, the last one applied wins.

**What this means in practice.**

- When a device is signed out, everything it signed that the device signing it out hadn't already seen is ignored (rule 4), including devices it added and everything those devices signed. The exception is sign-outs and revocations by it, or by devices it added: those are judged on their own, so they count until the master acts.
- `prev` can't be checked, so a stolen device can fake it to make a sign-out or revocation look old. Until the master acts, a stolen device can therefore sign out any other ordinary device and revoke any client, and a device signed out like that has its work put on hold by rule 4.
- The master repairs all of it. The aza app shows the stolen device's changes, the person picks the last one they trust as `keep`, and the master removes the device. Everything the stolen device signed after `keep` is discarded, including its sign-outs and revocations and every device it added after `keep`. The devices and clients it attacked come back with their work, and its changes up to `keep` count even if someone signed it out without having seen them.
- A master removal is final. If the master removes an honest device by mistake, that machine makes new keys and is added again.
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

A client gets permission through a **certificate**: a statement signed by a device, which the client keeps. It is not published in the change log, so nobody can see which apps an identity uses.

```json
{
  "identity": "9f2c…",
  "node": "https://node.example",
  "app": "coolgame.com",
  "client": "<client signing public key>",
  "enc": "<client encryption public key, only with the read scope>",
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

**Getting a certificate.** The client makes a **request** holding its app ID, client key, encryption key (if asking for `read`), the scopes it wants, and a **return URL**. The return URL must be an `https` URL whose host is exactly the app ID. The aza app refuses any request whose return URL isn't, because the return URL is how the aza app knows the certificate can only reach the real app:

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

**Revoking.** A `revoke-client` change puts only the client key's fingerprint into the log, so it doesn't reveal which app the client belonged to.

**The list of approvals.** The aza app keeps at most 64 certificates in effect per identity. It stores the list of them as its own sync data (section 9), so every device of the identity shows the same apps, clients and scopes, and any of them can revoke one.

## 8. Backup file

A **backup file** holds a device's private keys, encrypted with a password. It is how the master is meant to be kept, but any device can be saved this way.

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
- the device's private signing and encryption keys,
- the home node URL.

A password is required. Only the aza app opens backup files. To use one, you open it in the aza app on a phone or computer; the aza app uses the keys for that session only, for example to add the machine as a new device, and then forgets them.

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

The aza app writes an envelope of the data secret for each current device, including the master, and an envelope of the app key for each client whose certificate has `read`. A reader only uses an envelope signed by a device that is current at the end of the log, and checks the opened secret against its `check`. So a node or a signed-out device can't slip in a secret of its own. When a device stops being current, the aza app re-signs every envelope that device had signed. Readers may open envelopes for any secret the log has announced, so items not yet moved to the current secret stay readable. A new device or client gets its envelope from the home node and opens it with its own private encryption key. The backup file doesn't need the data secret, because the master's envelope is on the home node.

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

**Replacing the data secret.** A device that has been signed out or removed, and a client whose `read` access was revoked, still know the secret or app key they were given. Only the master replaces the data secret, so a stolen device can never plant one it knows. Right after a sign-out or a revocation of a `read` client, the aza app urges the person to open the master's backup file to do it, and does it automatically whenever the master removes a device. To replace it, the aza app makes a new data secret, signs a `new-secret` change, writes new envelopes for every current device and every `read` client, and re-encrypts all of the identity's sync data under the new app keys. A node refuses writes under any secret other than the current one, so a client that hasn't caught up gets an error, fetches its new envelope and tries again. Any device that finds an item still under an older secret, for example because re-encryption was interrupted, re-encrypts it.

## 10. Nodes

A **node** is a server that stores change logs, sync data and envelopes. Anyone can run one. Each node's operator decides what it stores, and may refuse any upload. aza runs a node too, and in the protocol it is like any other.

An identity's **home node** is the node it chose, with a `set-home` change, to hold its change log, sync data and envelopes. During setup the aza app suggests aza's node; any node works. The aza node stores up to 1 MB of sync data and envelopes per identity; other nodes set their own limits. The aza node never counts the change log toward that limit, so an identity can always upload a sign-out or removal, however full its storage is.

**Moving.** Before signing a `set-home` for a new node, the aza app copies the change log, sync data, envelopes and certificates there. After the log gains that `set-home`, the old node keeps answering requests for the log for at least one year. Anyone who still has the old address, including clients whose certificate names the old node, sees the latest `set-home` and follows it.

**Copies.** A node may also keep copies of other identities' change logs, for example of people its own identities interact with, so they can still be found after their old node disappears. Whether it does is up to its operator.

### 10.1 Node API

Every node answers these HTTP requests under `https://<node>/aza/v1/`. Request and response bodies are CBOR (`content-type: application/cbor`).

| Request | Who may make it | What it does |
|---|---|---|
| `GET log/{identity}` | anyone | returns every change the node holds for the identity |
| `POST log/{identity}` | anyone | uploads changes; the node keeps those with valid signatures that it chooses to store, and checks a new identity's work against its admission price (section 11) |
| `GET sync/{identity}/{app}?since={n}` | a current device, or a client with `read` for `app` | returns the items the node has stored or changed since its own counter `n`, plus the new counter |
| `PUT sync/{identity}/{app}/{name}` | a current device, or a client with `write` for `app` | stores one item; refused unless `version` is exactly one more than the stored one and `secret` is the current secret |
| `POST certificates/{identity}` | anyone | stores a certificate, so its client can then authenticate by fingerprint |
| `GET envelopes/{identity}/{holder}` | the holder | returns the envelopes for that device ID or client key fingerprint |
| `POST envelopes/{identity}` | a current device | stores envelopes; the node keeps every valid one, and readers choose as in section 9 |
| `GET picture?url={url}` | a current device or client of an identity whose home node this is | optional: fetches a profile picture on the identity's behalf, so the image's host never learns who is looking at whom |

Requests that need permission carry an `aza-auth` header: the base64url encoding of a CBOR object with the identity ID, `by` (a device ID, or a client key fingerprint whose certificate the node already holds), `time` (Unix seconds), a random 16-byte `nonce` and `sig`. `sig` is `by`'s signature over the CBOR array `[host, method, path with query, time, nonce, hash of the body]`. The header is about 4.6 KB. The node accepts it only if `host` is its own, `time` is within 5 minutes of its clock, it hasn't seen this `nonce` in that time, and `by` has permission after reading the newest log it holds:

- a device: it is current;
- a client: at least one certificate the node holds for that client key passes all of these: its `identity` and `app` match the path, its signing device is current, the client isn't revoked, and it has the scope the request needs.

## 11. Proof of work

Creating an identity costs computing time, so that nobody can cheaply create millions of identities and fill nodes with them.

The genesis change's `counter` is a number the creator picks. Run Argon2id over the genesis change (everything except `sig`), with 64 MiB of memory, 1 iteration, 1 lane, the salt `"aza work v1"` and a 32-byte output. The identity's **work** is how many zero bits that output starts with. The creator tries different counters until the work is high enough; each extra bit doubles the average number of tries. Checking takes a single run.

Argon2id is [memory-hard](https://en.wikipedia.org/wiki/Memory-hard_function): each run needs a large block of memory, which makes graphics cards and custom chips much less of an advantage over a phone.

The **minimum work** in version 1 is 6: about 2^6 = 64 tries, aimed at roughly 5 seconds on a 2022 iPhone. A genesis change below it is invalid. A node may also set its own, higher **admission price**: it refuses to store identities whose work is below it, for example during a spam attack. Work is fixed when the identity is created, so an identity created with little work can only use nodes that accept that amount. Later versions raise the minimum as hardware gets faster.

## 12. Versions

Every change has a version number `v`. Software that meets a field it doesn't know inside a change it otherwise understands ignores the field, so new optional fields don't break older software.

Software that meets a change type it doesn't know, or a higher `v` than it supports, checks whether it is discarded (section 5.4, step 3) and rules 1, 2 and 4 of step 5. If it isn't discarded and would pass them, the software treats the whole log as unreadable until it is updated, because skipping that change could give it a different list of devices from everyone else. If not, it ignores the change.

The spec lives in a public repository that anyone can fork. Each node and app chooses which spec it follows.

## 13. Walkthrough

aiden, whose domain is `sidny.me`:

1. **Create.** The aza app on aiden's iPhone makes the master's keys and finds a counter giving enough work. The master signs the genesis change, whose hash is aiden's identity ID. The master then signs `add-device` for the iPhone's own device, `set-profile` (name "aiden") and `set-home` (aza's node). The app makes the first data secret, seals envelopes of it for the master and the iPhone, and uploads the log and envelopes to aza's node.
2. **Back up.** The app saves the master's keys into a backup file protected by aiden's password and deletes them from the iPhone. Nothing in the log changes.
3. **Laptop.** The aza app on aiden's Mac makes the Mac's keys and shows a QR code holding its public keys. aiden scans it with the iPhone, which signs `add-device` for the Mac and seals an envelope of the data secret for it.
4. **Handle.** aiden adds `_aza.sidny.me TXT "aza=<identity ID> node=<aza node URL>"` and signs `set-profile` with `handle: "sidny.me"`. Apps now show `@sidny.me`.
5. **A game.** coolgame on the Mac asks to sign in with scope `sign-in` and a return URL on `coolgame.com`. The Mac's aza app shows the request, aiden approves, and the Mac signs a certificate and opens the return URL, which only the real coolgame can receive. coolgame's server fetches aiden's log, checks the certificate (section 7) and has the game sign a challenge. Nothing about coolgame appears in aiden's change log.
6. **Stolen phone.** The Mac downloads the newest log and signs `sign-out` for the iPhone. Anything the thief did with the phone that the Mac hadn't seen is ignored, except sign-outs and revocations (section 5.4), and certificates the iPhone signed stop working. To make it final, and to undo anything the thief did, such as signing out the Mac, aiden opens the backup file in the aza app and removes the iPhone with the master, keeping its changes up to the last one aiden trusts. The aza app then replaces the data secret, so the phone can't read anything written after that.
7. **Offline apps.** Heavier works with none of this. Turning on aza sync makes Heavier ask for a certificate with `read` and `write`. It gets its app key from its envelope on aiden's home node, then uploads encrypted workouts there.
