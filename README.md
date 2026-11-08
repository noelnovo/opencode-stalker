# OpenCode Stalker

A small OpenCode V2 server plugin that sends a generic Android data message when
a live question form is created. It publishes directly to Firebase Cloud
Messaging from the OpenCode process: no separate notification subscriber,
sender service, Unix socket or public callback endpoint.

This repository contains the direct-plugin **0.3.1** source and synthetic tests
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

Each registration has `schema` equal to integer `1`, `enabled` as a boolean,
`package` matching the source pin, and its private FCM registration `token`.
Use clearly synthetic data in tests. Actual keys, registration tokens and device
identifiers belong only in the protected secret-management lifecycle.

This plugin does not fetch Vault secrets itself. A one-shot injector must be run
again after an authorized key/device change; this is not continuous rotation or
boot-time injection. Never give a sender an OpenCode administrator login token.

## Test and audit

```sh
npm test
python3 scripts/audit-public.py
```

The tests use generated ephemeral RSA keys, fake tokens, metadata fixtures and
fake HTTP responses. They do not contact Google, Vault, an Android device, or a
running OpenCode server. Guard tests cover changed legitimate PIDs and rejection
of wrong UID/HOME/cwd/arguments/parent/profile/helper identities.

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
