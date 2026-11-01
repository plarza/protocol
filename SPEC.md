# aza identity

This document specifies how accounts work across aza: one account that signs in to every aza app and to apps built by anyone else, without an accounts server. It describes only what is decided. Examples are written as JSON for readability; the exact byte encoding is not specified yet.

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
- The **master** is one special device per identity. It is created with the identity, never changes and can't be signed out or removed. It alone can remove other devices for good.
- The **aza app** is aza's own app that holds devices and approves sign-ins.
- A **node** is a server that stores identities and app data. Anyone can run one.
- An identity's **home node** is the node it has chosen to store its data.
- An **app** is any service people sign in to with an aza identity, such as Heavier or someone's video game.
- A **client** is one program acting for an identity inside an app, like the iPhone version of a messenger. Clients get limited permission from a device and never hold a device key.
- **Sync data** is an app's data, encrypted and stored on a node so its clients can share it.
- **Proof of work** is a computing cost paid once when an identity is created, to make mass-creating identities expensive.

## 3. Cryptography

Everything in aza is built from four pieces.

**Key pair.** A private key and a public key. The private key signs data; the public key lets anyone check those signatures. aza uses a *hybrid* key pair: an [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) key pair plus an [ML-DSA-65](https://en.wikipedia.org/wiki/ML-DSA) key pair, used together. ML-DSA is designed to survive [quantum computers](https://en.wikipedia.org/wiki/Post-quantum_cryptography); Ed25519 is older and well understood. Using both means an attacker has to break both. A hybrid public key is 32 + 1952 = 1984 bytes.

**Signature.** Data signed with both private keys. It is valid only if both halves check out against the public key. A hybrid signature is 64 + 3309 = 3373 bytes.

**Hash.** [SHA-256](https://en.wikipedia.org/wiki/SHA-2): 32 bytes, written as 64 lowercase hex characters.

**Fingerprint.** The hash of a public key. It's a short way to name a key: 32 bytes instead of 1984.

## 4. Devices and the master

A **device** is a key pair that controls an identity. Its private key is stored in the **aza app** on a phone or computer (only on that machine, never synced to any cloud) or in a **backup file** (section 8).

The **aza app** is aza's standalone app for iPhone, Mac and other platforms. It is the only program that ever handles device keys. Its jobs are creating identities, adding devices and approving sign-ins.

The **master** is the device whose key is in the identity's first change (section 5.2). It is fixed for the life of the identity: no change can remove it or replace it. Its job is repair: if a device is stolen, the master removes it and throws away everything it signed after a point the person chooses (section 5.4). The flip side: if the master itself is stolen, or its backup file's password guessed, nothing can stop the thief, and the identity has to be abandoned. That's why it belongs in a backup file kept offline.

When an identity is created, the aza app makes two key pairs: the master and a device for that phone or computer. The aza app strongly recommends saving the master into a backup file and then deleting it from the machine. Until then, the master's private key is kept in the aza app on that machine. Where the master is kept doesn't change the identity: it's the same key either way.

Every device other than the master is an **ordinary device**. Every device can add devices, sign out ordinary devices other than itself, change the profile and revoke clients. Only the master can remove a device. **Signing out** stops a device straight away, for example a phone that was just stolen. **Removing** is final, and it replaces any sign-outs of that device: the master decides what of the device's history to keep.

A device is **current** from when it is added until it is signed out or removed (section 5.4 makes this exact). An identity can have at most 64 devices that haven't been removed; signed-out devices count until the master removes them. A machine whose device was removed makes a new key pair before it is added again.

## 5. Identity

An identity is stored as a **change log**: a list of **changes**, each signed by one of its devices. Reading the log tells you everything about the identity: its devices, its profile and so on.

### 5.1 Changes

Every change has the same fields:

```json
{
  "v": 1,
  "identity": "9f2c…",
  "prev": ["41d0…"],
  "time": 1793500000,
  "by": "c87a…",
  "body": { "type": "add-device", "key": "…", "label": "MacBook" },
  "sig": "…"
}
```

| Field | Meaning |
|---|---|
| `v` | Protocol version the change follows (section 11). |
| `identity` | The identity ID (section 5.2). Absent in the genesis change. |
| `prev` | Hashes of the newest changes the signing device knew about when it signed. Absent in the genesis change. Usually one hash; more than one when the device had seen two changes made at the same time. The signer chooses `prev` and nobody can check it was honest; section 5.4 says what a dishonest `prev` can and can't do. |
| `time` | Unix seconds, as claimed by the signer. Shown to people, never used to decide anything. |
| `by` | Device ID (section 5.2) of the device that signed. |
| `body` | What the change does (section 5.3). |
| `sig` | Signature by device `by` over all the other fields. |

The **ancestors** of a change are the changes listed in its `prev`, the changes listed in their `prev`, and so on back to the start. A change only counts as an ancestor if it is actually in the log.

### 5.2 The genesis change and the identity ID

The **genesis change** is the first change of every identity. Its body holds the master's public key and the proof of work (section 10). It is signed by the master.

The **identity ID** is the hash of the genesis change. It never changes. Everything that refers to an identity uses its identity ID.

A **device ID** names one device: it is the hash of the `add-device` change that added it. The master's device ID is the identity ID. Devices are named this way rather than by their key so that a removal applies to one specific addition, never to some other addition of the same key.

### 5.3 Change types

| `body.type` | Fields | Who may sign it | Effect |
|---|---|---|---|
| `genesis` | `key`, `counter` | the master | creates the identity |
| `add-device` | `key`, `label` | any device | adds a device. Not allowed if the identity would then have more than 64 devices that haven't been removed. |
| `sign-out` | `device` (device ID) | any device | signs out a current ordinary device other than the signer itself |
| `remove-device` | `device` (device ID), `keep` (change hash, optional) | the master only | removes a device for good. `device` must be the device ID of an `add-device` change among this change's ancestors. `keep`, if given, must be a change signed by `device` and an ancestor of this change. |
| `set-profile` | `name`, `picture`, `handle` | any device | replaces the profile (section 6) |
| `set-home` | `node` (URL) | any device | sets the home node (section 9) |
| `revoke-client` | `client` (fingerprint) | any device | revokes a client (section 7) |

### 5.4 Reading the log

Two devices can sign changes without knowing about each other. For example, aiden's phone is on a plane and adds a device while aiden's laptop updates the profile. Both changes list the same change in `prev`. Two changes are **concurrent** when neither is an ancestor of the other.

A log is read in four steps. Each step only uses the results of the steps before it.

**Step 1: master removals.** Every `remove-device` change with a valid signature by the master that follows the rules in section 5.3 is a **master removal**. The master can't be signed out or removed, so nothing else is needed to decide these. If the master removes the same device more than once, a change by it survives only if it is the `keep`, or an ancestor of the `keep`, of every one of those removals (one without `keep` discards everything).

**Step 2: discarded changes.** A change signed by device D is **discarded** if:

- there is a master removal of D, and the change is neither that removal's `keep` nor an ancestor of it (with no `keep`, everything D signed is discarded); or
- the `add-device` change that added D is itself discarded.

Discarded changes are ignored from here on. In other words, the master removal draws a line through the removed device's history: everything up to `keep` stays, and everything after it is gone, including any devices it added after that point and everything they signed.

**Step 3: sign-outs and revocations.** Two kinds of change are **judged on their own**: read a log made of only the change's ancestors (by all four steps), then check the change against rules 1 to 3 of step 4 at the end of that reading. Whether a change is discarded is always decided on the whole log, by step 2.

- A **sign-out** of device D is a `sign-out` change for D that isn't discarded, is allowed when judged on its own, and D has no master removal. (Once the master removes D, the removal's `keep` alone decides what of D survives.)
- A **revocation** is a `revoke-client` change that isn't discarded and is allowed when judged on its own.

Judging on their own means two devices that sign each other out at the same moment are both signed out, rather than whoever happens to come first winning.

**Step 4: applying changes.** Go through the changes that aren't discarded in **reading order**: repeatedly take, out of the changes not yet taken whose ancestors have all been taken, the one with the smallest hash. That puts every change after its ancestors and gives everyone the same order. A device is **current** at a given point if it was added by a change already applied (or is the master), and no sign-out or master removal of it has been reached yet. Sign-outs, revocations and master removals take effect when they are reached. Any other change is applied if all of these hold:

1. its signature is valid for the key of device `by`;
2. `by` is a current device at this point;
3. its body follows the rules in section 5.3;
4. it is an ancestor of every sign-out of `by`.

When several changes set the same thing, such as two `set-profile`s, the last one applied wins.

**What this means in practice.**

- When a device is signed out, everything it signed that the device signing it out hadn't already seen is ignored (rule 4), including devices it added and everything those devices signed. The exception is sign-outs and revocations by it, or by devices it added: those are judged on their own, so they count until the master acts.
- `prev` can't be checked, so a stolen device can fake it to make a sign-out or revocation look old. Until the master acts, a stolen device can therefore sign out any other ordinary device and revoke any client, and a device signed out like that has its work put on hold by rule 4.
- The master repairs all of it. The aza app shows the stolen device's changes, the person picks the last one they trust as `keep`, and the master removes the device. Everything the stolen device signed after `keep` is discarded, including its sign-outs and revocations and every device it added after `keep`. The devices and clients it attacked come back with their work, and its changes up to `keep` count even if someone signed it out without having seen them.
- A master removal is final. If the master removes an honest device by mistake, that machine makes a new key and is added again.
- Additions that come back after a repair count toward the 64-device limit from their original place in reading order. So if the identity was at the limit, a later addition can fail; the aza app warns before signing a removal that would cause this.

**Example: a stolen phone.** A thief steals aiden's unlocked phone and adds the thief's own device. aiden's laptop, not having seen that, signs out the phone. The thief's `add-device` isn't an ancestor of that sign-out, so rule 4 ignores it, and the thief's device never becomes current. Its sign-outs and revocations still count for now, and so do the phone's: the thief uses the phone to sign out the laptop, faking `prev` so it looks older, and now both are signed out. aiden opens the master's backup file in the aza app and removes the phone with `keep` set to the phone's last change before the theft. The thief's sign-out of the laptop and everything the thief's device did are discarded, the laptop is current again, and everything it did since counts.

The aza app downloads the newest log from the home node before signing any change, so that it doesn't throw away legitimate changes it simply hadn't seen yet.

## 6. Profile

The **profile** is what other people see. It has three fields, all set by `set-profile`:

- **`name`**: the display name. Any text up to 64 characters. Not unique: anyone can be "aiden".
- **`picture`**: an `https` URL of an image, up to 2048 characters.
- **`handle`**: optional. A domain the identity owns.

A **handle** is a [registrable domain](https://en.wikipedia.org/wiki/Public_Suffix_List): the part of a domain you can buy, like `sidny.me` or `example.com.au`, but never a subdomain like `blog.sidny.me`. To prove it, the owner adds this DNS record:

```
_aza.sidny.me  TXT  "aza=<identity ID> node=<home node URL>"
```

An app shows a handle only after looking up that record through a public [DNS-over-HTTPS](https://en.wikipedia.org/wiki/DNS_over_HTTPS) resolver and finding the identity's ID in it. Otherwise it shows the display name only. The `node=` part lets someone who only knows the handle find the change log. If the identity moves to another home node, the owner updates the record.

## 7. Apps, clients and certificates

An **app** is a service, named by a domain it controls: `heavier.aza.network`, `coolgame.com`. That domain is its **app ID**.

A **client** is one piece of software acting for an identity inside one app. The iPhone and Mac versions of a messenger are two clients of one app. Each client makes its own key pair, the **client key**. Clients never see device keys.

A client gets permission through a **certificate**: a statement signed by a device, which the client keeps. It is not published in the change log, so nobody can see which apps an identity uses.

```json
{
  "identity": "9f2c…",
  "node": "https://node.example",
  "app": "coolgame.com",
  "client": "<client public key>",
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
| `write` | storing sync data for this app |

**Getting a certificate.** The client sends a request (its app ID, client key and the scopes it wants) to the aza app. On the same machine it opens the aza app directly; from another machine it shows a QR code that the aza app scans. The aza app shows the request, and if the person approves, a device signs the certificate and the aza app returns it to the client.

**Checking a certificate.** Anyone, such as a game's server, gets the change log starting from the certificate's `node` (and then the home node named by the log's latest `set-home`, if different), and accepts the certificate only if:

1. its signature is valid;
2. device `by` is current at the end of the log (not signed out or removed);
3. the log has no revocation of this client key's fingerprint;
4. its `app` is the app doing the checking;
5. the client proves it holds the client key, by signing a fresh random challenge from the checker. A copied certificate is useless without the client's private key.

A node can't forge changes, but it can hide the newest ones. A checker that only sees an out-of-date log may accept a certificate whose device has since been signed out or removed, until it sees the newer log.

**Revoking.** A `revoke-client` change puts only the client key's fingerprint into the log, so it doesn't reveal which app the client belonged to.

**The list of approvals.** The aza app keeps at most 64 certificates in effect per identity. It stores the list of them as its own sync data (section 9), so every device of the identity shows the same apps, clients and scopes, and any of them can revoke one.

## 8. Backup file

A **backup file** holds a device's private key, encrypted with a password. It is how the master is meant to be kept, but any device can be saved this way.

```json
{
  "format": 1,
  "argon2id": { "salt": "…", "memory": 65536, "iterations": 3, "parallelism": 1 },
  "nonce": "…",
  "ciphertext": "…"
}
```

The password is turned into a 256-bit key with [Argon2id](https://en.wikipedia.org/wiki/Argon2), a deliberately slow and memory-hungry function that makes guessing passwords expensive. `salt`, `memory` (in KiB; 65536 KiB is 64 MiB), `iterations` and `parallelism` are its settings, chosen when the file is made. That key encrypts the contents with [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode); `nonce` is the random 12-byte value that AES-256-GCM needs for each encryption. The encrypted contents are:

- the identity ID,
- the device private key,
- the home node URL.

A password is required. Only the aza app opens backup files. To use one, you open it in the aza app on a phone or computer; the aza app uses the key for that session only, for example to add the machine as a new device, and then forgets it.

## 9. Nodes

A **node** is a server that stores change logs and sync data and hands change logs to anyone who asks. Anyone can run one. Each node's operator decides what it stores. aza runs a node too, and in the protocol it is like any other.

An identity's **home node** is the node it chose, with a `set-home` change, to hold its change log and sync data. During setup the aza app suggests aza's node; any node works.

**Sync data** is an app's data for one identity, encrypted before upload so the node can't read it. Each piece is signed by whoever uploaded it. A node stores sync data only if it is signed by a current device of the identity or by a client with a valid `write` certificate for that app, and serves it only to a current device or a client with a valid `read` certificate for that app. The aza node stores up to 1 MB of sync data per identity; other nodes set their own limits.

**Profile pictures.** A node may fetch profile pictures on behalf of the identities whose home node it is, so the image's host never learns who is looking at whom.

## 10. Proof of work

Creating an identity costs computing time, so that nobody can cheaply create millions of identities and fill nodes with them.

The genesis change's `counter` is a number the creator picks. Run Argon2id over the genesis change (everything except `sig`). The identity's **work** is how many zero bits the result starts with. The creator tries different counters until the work is high enough; each extra bit doubles the average number of tries. For example, if one Argon2id run takes 0.05 seconds on a phone, reaching a work of 6 takes about 2^6 = 64 tries, or about 3 seconds. Checking takes a single run.

Argon2id is [memory-hard](https://en.wikipedia.org/wiki/Memory-hard_function): each run needs a large block of memory, which makes graphics cards and custom chips much less of an advantage over a phone.

Each protocol version sets the Argon2id settings and a **minimum work**. A genesis change below it is invalid. A node may also set its own, higher **admission price**: it refuses to store identities whose work is below it, for example during a spam attack. Work is fixed when the identity is created, so an identity created with little work can only use nodes that accept that amount.

## 11. Versions

Every change has a version number `v`. Software that meets a field it doesn't know inside a change it otherwise understands ignores the field, so new optional fields don't break older software.

Software that meets a change type it doesn't know, or a higher `v` than it supports, checks whether it is discarded (section 5.4, step 2) and rules 1, 2 and 4 of step 4. If it isn't discarded and would pass them, the software treats the whole log as unreadable until it is updated, because skipping that change could give it a different list of devices from everyone else. If not, it ignores the change.

The spec lives in a public repository that anyone can fork. Each node and app chooses which spec it follows.

## 12. Walkthrough

aiden, whose domain is `sidny.me`:

1. **Create.** The aza app on aiden's iPhone makes the master and finds a counter giving enough work. The master signs the genesis change, whose hash is aiden's identity ID. The master then signs `add-device` for the iPhone's own device key, `set-profile` (name "aiden") and `set-home` (aza's node), and the app uploads the log there.
2. **Back up.** The app saves the master into a backup file protected by aiden's password and deletes it from the iPhone. Nothing in the log changes.
3. **Laptop.** The aza app on aiden's Mac shows a QR code holding the Mac's public key. aiden scans it with the iPhone, which signs `add-device` for the Mac.
4. **Handle.** aiden adds `_aza.sidny.me TXT "aza=<identity ID> node=<aza node URL>"` and signs `set-profile` with `handle: "sidny.me"`. Apps now show `@sidny.me`.
5. **A game.** coolgame on the Mac asks to sign in with scope `sign-in`. The Mac's aza app shows the request, aiden approves, and the Mac signs a certificate for the game's client key. The game's server fetches aiden's log, checks the certificate (section 7) and has the game sign a challenge. Nothing about coolgame appears in aiden's change log.
6. **Stolen phone.** The Mac downloads the newest log and signs `sign-out` for the iPhone. Anything the thief did with the phone that the Mac hadn't seen is ignored, except sign-outs and revocations (section 5.4), and certificates the iPhone signed stop working. To make it final, and to undo anything the thief did, such as signing out the Mac, aiden opens the backup file in the aza app and removes the iPhone with the master, keeping its changes up to the last one aiden trusts.
7. **Offline apps.** Heavier works with none of this. Turning on aza sync makes Heavier ask for a certificate with `read` and `write`, then upload encrypted workouts to aiden's home node.
