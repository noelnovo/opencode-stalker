# OpenCode Stalker

A small OpenCode V2 server plugin that sends a generic Android data message when
a live question form is created. It publishes directly to Firebase Cloud
Messaging from the OpenCode process: no separate notification subscriber,
sender service, Unix socket or public callback endpoint.

This repository contains the direct-plugin **0.3.2** source and synthetic tests
only. It targets the OpenCode **2.0.41** plugin contract. It is not an Android app,
an OpenCode fork, a credential bundle, or an npm release.

## How it works

- Every Location instance subscribes through `ctx.event.subscribe` in-process.
- Events are filtered manually: `form.created` with `metadata.kind === "question"`.
  Reply/cancellation events drop queued work.
- A process-shared queue handles Location/global duplicates without awaiting
  network operations in the event-consumption loop.
- Queue: 64 items. Dedup: 512 entries. TTL: at most 300 seconds.
- HTTPS requests have five-second timeouts, bounded response bodies and at most
  two attempts per item. Cleanup aborts subscriptions and pending requests.
- Messages contain only `schema: "1"`, `kind: "question"`, and an opaque ASCII
  `event_id`. Android priority is HIGH and the package is restricted.
  `notification` and `android_v2` fields are omitted; the Android app owns
  validation, local display and opt-out.

## Install safely

Requires Linux procfs and a compatible OpenCode server. No runtime npm
dependencies are needed.

1. Review the source and your deployment identity before loading a plugin.
2. Match the deliberately **deployment-pinned** constants in
   `plugin/identity.mjs` to your real managed service: UID, HOME, working
   directory, executable/arguments and immediate Vault Agent executable/profile.
   Match the Firebase project and Android package constants in `plugin/index.mjs`
   to your approved sender/receiver. The Firebase/package pins in this public
   source are clearly synthetic examples, not a live deployment configuration.
   Keep your reviewed deployment-specific substitutions outside public Git.
   Do not remove the guard or replace it with an allow-all check.
3. Install the reviewed plugin directory with administrative ownership; do not
   allow an unrelated user to replace its code.
4. Use your existing secret manager and a least-privilege credential injector to
   render the private JSON file described below. Never commit that file.
5. Add a local plugin entry to your OpenCode configuration, preserving every
   other setting. A generic example (replace the paths locally):

   ```jsonc
   {
     "plugins": [
       {
         "package": "/example/plugins/opencode-stalker/plugin",
         "options": {
           "credentialFile": "/example/private/stalker-credentials.json"
         }
       }
     ]
   }
   ```

Use supported plugin/config file watching when available and verified safe for
your version. Do not use a Location reload as a harmless plugin reload: pending
input may be cancelled. Coordinate any genuinely required service restart with
the server owner.

### Managed-process guard

PID is not a persistent identity. Normal managed restarts are accepted when the
same service identity matches. The guard reads bounded self/parent proc metadata
and matches the **exact OS invocation**, not compiled Bun's JavaScript argv.
Missing, malformed or mismatched metadata excludes the process. Helpers and
standalone fixtures have no configuration override to bypass this guard.

This prevents accidental helper notifications; it is **not** a same-UID security
sandbox. Service/profile/executable changes require an explicit guard review.

### Private credential-file contract

The file must be a regular, single-link file owned by the OpenCode process user,
mode `0600`, within a protected directory. Its fields are:

| Field | Type | Meaning |
|---|---|---|
| `fcm.PROJECT_ID` | string | Approved Firebase project, matching the source pin |
| `fcm.SERVICE_ACCOUNT_JSON` | JSON-encoded string | Approved Google sender service-account object |
| `devices.DEVICES_JSON` | JSON-encoded string | Array of owner-enrolled receiver registrations |

Each registration has `schema` equal to integer `1`, a stable `device_id` (1–128
ASCII letters/digits/underscore/hyphen), `enabled` as a boolean, and `package`
matching the source pin. The registry has at most 100 records. Each enabled
installation uses one private `topic`, or a legacy FCM registration `token`:

- `topic`: exactly 51 characters, matching `^stalker_[A-Za-z0-9_-]{43}$`.
  No `/topics/` prefix, padding, whitespace or extra characters.
- Legacy `token`: 20–4096 ASCII letters/digits/underscore/hyphen/colon/dot.
- Topic wins over token for the same device, even across duplicate records;
  **never dual-send** to an installation. A present invalid topic does not fall
  back to a possibly stale token. Conflicting topics/tokens fail closed. Any
  disabled or malformed-enabled record for that installation suppresses it.
  Identical selected routes are also deduplicated across device IDs.
- Invalid schema/package/device identifiers are ignored. Duplicate grouping is
  scoped to valid schema/package/ID envelopes; never use malformed records as
  disable requests.

Use clearly synthetic data in tests. Actual keys, topics, registration tokens and
device identifiers belong only in the protected secret-management lifecycle.
The sender emits `message.topic` for topics, `message.token` for legacy devices,
and no other target. Existing token-only UNREGISTERED quarantine does not apply
to topic routes. Generic HTTP status receipts never contain route values or
Google response bodies; a local 204 means no eligible target, not FCM acceptance.

### Stable per-installation Android routing

The Android app generates **32 cryptographically random bytes once**, encodes
them with Base64URL without padding (43 characters), and prefixes `stalker_`.
It encrypts/preserves this app-managed topic and installation ID. Call the Firebase
SDK's `subscribeToTopic` at initial setup **and again from `onNewToken`**. Topic
subscriptions must not be assumed to migrate automatically after FID/token
changes. Use SDK subscription retry, not application polling, a public enrollment
endpoint, or an embedded Firebase Admin credential. Token refresh then requires
no recurring operator/ADB registration update for this installation.

Notification off is a **local receiver gate** plus clearing current notifications.
Keep the topic, installation ID, FCM token/registration and subscription on
off/on. Do not call `deleteToken`, clear enrollment or unsubscribe on a UI toggle.
Re-enable restores local display without changing the server route. Delivery
while disabled may still occur; the receiver must discard it locally.

**Membership is not an authenticated ACL.** Anyone who learns a topic name can
subscribe; its 256-bit random name makes guessing impractical, not membership
authenticated. Treat it as secret capability-like routing metadata: never log,
publish, paste into tool parameters, or put it in Git/receipts. Only the existing
generic schema/kind/opaque event ID may be sent. Never send question contents,
answers, approvals, commands or other private text. Keep restricted Android
package, HIGH priority, data-only and TTL at most 300 seconds unchanged. No
`notification` or `android_v2` payload is introduced. Existing FCM sender rights
are used; no Google IAM expansion or new OpenCode identity is needed.

App-data wipe/reinstall/new installation loses the app-managed secret and needs
a **new one-time private route enrollment**. This does not claim to solve that
case or automatically transfer a route between installations. Topics can also
have different fanout/latency behavior from direct tokens; delivery is best effort.

### Private one-time migration envelope

After the app confirms SDK subscription success, the operator delivers one UTF-8
JSON object privately to the agreed root-owned `topic-route.json` intake file:

| Field | Type / required value |
|---|---|
| `schema` | integer `1` |
| `device_id` | existing installation ID (exact match, no new device) |
| `package` | approved Android package |
| `enabled` | boolean `true` |
| `topic` | private 51-character topic described above |
| `project_id` | approved Firebase project, verified by intake operator |

The parent confirms subscription success separately before upload; an export
alone or an FCM validate-only 200 cannot prove Android subscription or receipt.
Do not include a raw token, key, question text or an Admin credential. Transfer
over independently pinned SSH only, with root `0700` directory and regular,
single-link root `0600` file, bounded to 16 KiB. No chat/MCP payload intake.

Follow-up must recheck current instructions, input ownership/type/size/schema,
exact authorized ID/package/project and all field types without printing values.
Read the current Vault registry/version privately, abort on unexpected concurrent
changes, and CAS-update **only that installation's route** (replace legacy token
with topic), preserving other devices/fields and sender credentials. Keep a
private before-state for scoped rollback; do not remove retained Vault history.
The stored registration uses schema/device_id/package/enabled/topic; project_id
is an intake check, not an FCM target field. Use the existing official Vault Agent
one-shot renderer and verify snapshot equality privately. Reactivate only this
plugin through a verified safe self-plugin mechanism, never a Core/Bridge restart
or Location reload. Validate, then send only the separately authorized single
test. Parent must confirm actual device receipt. Initial source implementation
does not authorize any of these live steps or claim migration/receipt completion.

This plugin does not fetch Vault secrets itself. A one-shot injector must be run
again after an authorized key/device change; this is not continuous rotation or
boot-time injection. Never give a sender an OpenCode administrator login token.

## Test and audit

```sh
npm test
python3 scripts/audit-public.py
```

The tests use generated ephemeral RSA keys, dynamically constructed fake topics,
fake tokens, metadata fixtures and
fake HTTP responses. They do not contact Google, Vault, an Android device, or a
running OpenCode server. Guard tests cover changed legitimate PIDs and rejection
of wrong UID/HOME/cwd/arguments/parent/profile/helper identities. Routing tests
cover topic/token validation, bounds, disabled/conflicting/duplicate records,
topic preference with no double-send, generic payload/log suppression, legacy
quarantine and topic expiration/cancellation. Queue/filter/dedup limits and the
managed identity implementation remain unchanged.

The publication audit checks the tracked file allowlist, every reachable commit
and branch, forbidden filenames, private-network/credential patterns and clean
standalone history. It prints counts/status only, never matching values.

## Limits

Live-only recovery: initial load, reload gaps and overflow may miss questions.
Retries may duplicate an accepted message; an already accepted/in-flight message
cannot reliably be recalled after settlement. FCM HTTP 200 means Google accepted
the send, **not** proof of Android receipt. The receiver must validate and dedup.

## Licensing

No license file or per-file license notice was present in the extracted source
snapshot. This extraction does not add a license grant. Ask the owner about
licensing before redistributing or incorporating the source.
