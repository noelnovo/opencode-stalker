import test from "node:test"
import assert from "node:assert/strict"
import { generateKeyPairSync, verify } from "node:crypto"
import { mkdtemp, writeFile, chmod, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { setup, Queue, DirectSender, message, eventID, readCredentials } from "../plugin/index.mjs"
import { isManagedServer, readManagedIdentity } from "../plugin/identity.mjs"

const created = (id = "frm_one", directory = "/a", kind = "question") => ({ type: "form.created",
  ...(directory === undefined ? {} : { location: { directory } }),
  data: { form: { id, sessionID: "ses_fixture", metadata: { kind }, title: "PRIVATE", fields: [{ text: "PRIVATE" }] } } })
const settled = (type, id = "frm_one", directory = "/a") => ({ type,
  ...(directory === undefined ? {} : { location: { directory } }), data: { id, answer: "PRIVATE" } })
const fixture = () => {
  let now = 1000
  const sent = []
  const q = new Queue({ send: async (item) => { sent.push(item.id); return 200 } }, () => {}, () => now)
  return { q, sent, advance: (ms) => { now += ms } }
}
test("manual filter never retains private content or other form kinds", () => {
  const { q } = fixture()
  assert.equal(q.accept({ type: "message.updated", data: { text: "PRIVATE" } }, "/a", 1), false)
  assert.equal(q.accept(created("frm_auth", "/a", "oauth"), "/a", 1), false)
  assert.equal(q.accept(created(), "/b", 1), false)
  assert.equal(q.accept(created(), "/a", 1), true)
  assert.equal(JSON.stringify([...q.pending.values()]).includes("PRIVATE"), false)
  assert.match([...q.pending.keys()][0], /^[a-f0-9]{64}$/)
})
test("both reply/cancel suppress queued sends, including settlement-first tombstones", async () => {
  for (const type of ["form.replied", "form.cancelled"]) {
    const { q, advance, sent } = fixture()
    q.accept(created(), "/a", 1); q.accept(settled(type), "/a", 1)
    q.accept(settled(type, "frm_late"), "/a", 1)
    assert.equal(q.accept(created("frm_late"), "/a", 1), false)
    advance(500); await q.tick(); assert.deepEqual(sent, [])
  }
})
test("per-location isolation and global multi-instance dedup", async () => {
  const { q, advance, sent } = fixture()
  q.accept(created(), "/a", 1); q.accept(created("frm_one", "/b"), "/b", 2)
  const global = created("frm_global"); delete global.location
  q.accept(global, "/a", 1); q.accept(global, "/b", 2)
  q.detach(1); assert.equal(q.pending.size, 2)
  advance(500); await q.tick(); await q.tick(); assert.equal(sent.length, 2)
  assert.equal(q.accept(global, "/b", 2), false)
})
test("queue64/dedup512 and TTL300 bounds", async () => {
  const { q, advance, sent } = fixture()
  for (let n = 0; n < 700; n++) q.accept(created("frm_" + n), "/a", 1)
  assert.equal(q.pending.size, 64); assert.equal(q.seen.size, 512)
  advance(300001); await q.tick(); assert.equal(q.pending.size, 0); assert.equal(q.seen.size, 0)
  assert.deepEqual(sent, [])
})
test("event intake never awaits network and cancellation aborts in-flight send", async () => {
  const { q, advance } = fixture()
  let release, aborted = false
  q.sender = { send: (_, signal) => new Promise((resolve) => {
    release = resolve; signal.addEventListener("abort", () => { aborted = true; resolve(410) })
  }) }
  q.accept(created(), "/a", 1); advance(500)
  const running = q.tick()
  q.accept(created("frm_two"), "/a", 1); assert.equal(q.pending.size, 2)
  q.accept(settled("form.cancelled"), "/a", 1); assert.equal(aborted, true)
  release(200); await running; q.close(); assert.equal(q.pending.size, 0)
})
test("limited retries and terminal failure do not loop", async () => {
  const { q, advance } = fixture(); let calls = 0
  q.sender = { send: async () => { calls++; return 503 } }
  q.accept(created(), "/a", 1); advance(500); await q.tick(); advance(500); await q.tick(); await q.tick()
  assert.equal(calls, 2); assert.equal(q.pending.size, 0)
})
test("HTTPv1 stable HIGH data-only payload and bounded TTL", () => {
  const payload = message("FAKE_DEVICE_TOKEN", eventID("/a", "frm_one"), 400000, 1000)
  assert.deepEqual(Object.keys(payload.message).sort(), ["android", "data", "token"])
  assert.deepEqual(Object.keys(payload.message.android).sort(), ["priority", "restricted_package_name", "ttl"])
  assert.equal(payload.message.android.ttl, "300s")
  assert.equal(payload.message.android.restricted_package_name, "com.example.dev")
  assert.deepEqual(Object.keys(payload.message.data).sort(), ["event_id", "kind", "schema"])
  assert.equal(JSON.stringify(payload).includes("notification"), false)
})
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const account = { type: "service_account", project_id: "example-project", client_email: "fixture@example.invalid",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }) }
const devices = [{ schema: 1, enabled: true, package: "com.example.dev", token: "SYNTHETIC_DEVICE_TOKEN_123" }]
test("direct sender signs valid OAuth assertion and posts only approved FCM payload", async () => {
  const calls = []
  const sender = new DirectSender(async () => ({ account, devices }), async (url, options) => {
    calls.push(url); assert.equal(options.redirect, "error"); assert.ok(options.signal)
    if (url.includes("oauth2")) {
      const assertion = options.body.get("assertion"), parts = assertion.split(".")
      assert.equal(verify("RSA-SHA256", Buffer.from(parts.slice(0, 2).join(".")), publicKey, Buffer.from(parts[2], "base64url")), true)
      const claims = JSON.parse(Buffer.from(parts[1], "base64url"))
      assert.equal(claims.aud, "https://oauth2.googleapis.com/token")
      return Response.json({ access_token: "SYNTHETIC_ACCESS_TOKEN", expires_in: 3600 })
    }
    assert.equal(url, "https://fcm.googleapis.com/v1/projects/example-project/messages:send")
    assert.deepEqual(Object.keys(JSON.parse(options.body).message.data).sort(), ["event_id", "kind", "schema"])
    return Response.json({ name: "fixture" })
  })
  assert.equal(await sender.send({ id: "a".repeat(64), expires: Date.now() + 300000 }, new AbortController().signal), 200)
  assert.equal(calls.length, 2)
})
test("oversized Google response fails closed", async () => {
  const sender = new DirectSender(async () => ({ account, devices }), async () => new Response("x".repeat(65537)))
  await assert.rejects(sender.send({ id: "a".repeat(64), expires: Date.now() + 300000 }, new AbortController().signal), /response_limit/)
})
test("credential permission checks and local opt-out", async () => {
  const dir = await mkdtemp(tmpdir() + "/stalker-unit-")
  const path = dir + "/credentials.json"
  try {
    await writeFile(path, JSON.stringify({ fcm: { PROJECT_ID: "example-project", SERVICE_ACCOUNT_JSON: JSON.stringify(account) },
      devices: { DEVICES_JSON: JSON.stringify([...devices, { ...devices[0], enabled: false }]) } }), { mode: 0o600 })
    assert.equal((await readCredentials(path)).devices.length, 1)
    await chmod(path, 0o644); await assert.rejects(readCredentials(path), /credential_file_invalid/)
  } finally { await rm(dir, { recursive: true }) }
})
const identity = (pid = 5001) => ({ pid, ppid: pid - 1, uid: 100, euid: 100,
  home: "/var/lib/opencode", cwd: "/srv/opencode", exe: "/usr/local/bin/opencode",
  argv: ["/usr/local/bin/opencode", "serve", "--hostname", "0.0.0.0", "--port", "4096"],
  parent: { exe: "/opt/hashicorp/vault/2.1.2/vault", uids: [100, 100, 100, 100],
    argv: ["/opt/hashicorp/vault/2.1.2/vault", "agent", "-config=/etc/vault-agent/native-opencode/config/agent.hcl"] } })
test("managed identity accepts different legitimate PIDs", () => {
  for (const pid of [5001, 6001, 7001]) assert.equal(isManagedServer(identity(pid)), true)
})
test("wrong UID/HOME/cwd/argv/parent/HCL and helper identities all fail closed", () => {
  const cases = [
    { uid: 0 }, { euid: 0 }, { home: "/root" }, { cwd: "/fixture" }, { exe: "/tmp/opencode" },
    { pid: undefined }, { ppid: 1 }, { ppid: 5001 },
    { argv: ["/usr/local/bin/opencode", "serve", "--hostname", "127.0.0.1", "--port", "4096"] },
    { argv: ["/usr/local/bin/opencode", "serve", "--hostname", "0.0.0.0", "--port", "49374"] },
    { argv: [...identity().argv, "--service"] }, { argv: identity().argv.slice(0, -1) },
    { parent: { ...identity().parent, exe: "/usr/bin/python3" } },
    { parent: { ...identity().parent, uids: [0, 0, 0, 0] } },
    { parent: { ...identity().parent, argv: [identity().parent.exe, "agent", "-config=/tmp/fixture.hcl"] } },
    { parent: { ...identity().parent, argv: [identity().parent.exe, "agent", "-config=/etc/vault-agent/native-opencode-bridge/config/agent.hcl"] } },
    { parent: { ...identity().parent, argv: [...identity().parent.argv, "-once"] } }, { parent: undefined },
  ]
  for (const variant of cases) assert.equal(isManagedServer({ ...identity(), ...variant }), false)
  assert.equal(isManagedServer(undefined), false)
})
test("actual metadata reader accepts synthetic proc metadata and handles missing metadata", async () => {
  const good = identity(7001)
  const runtime = { ...good, getuid: () => good.uid, geteuid: () => good.euid,
    env: { HOME: good.home }, cwd: () => good.cwd }
  const io = { readlink: async (p) => p === "/proc/self/exe" ? good.exe : good.parent.exe,
    boundedText: async (p) => p === "/proc/self/cmdline" ? good.argv.join("\0") + "\0" :
      p.endsWith("cmdline") ? good.parent.argv.join("\0") + "\0" : "Uid:\t100\t100\t100\t100\n" }
  // The compiled runtime's JS argv can contain an extra virtual entrypoint.
  runtime.argv = [good.exe, "/$bunfs/root/virtual-entrypoint.js", ...good.argv.slice(1)]
  assert.equal(isManagedServer(await readManagedIdentity(runtime, io)), true)
  assert.equal(await readManagedIdentity(runtime, { ...io, readlink: async () => { throw new Error("ENOENT") } }), undefined)
  assert.equal(isManagedServer(await readManagedIdentity(runtime, { ...io, boundedText: async () => "malformed" })), false)
})
test("managed setup duplicate instances and safe unload without any network", async () => {
  const ctx = (directory) => ({ options: { credentialFile: "/nonexistent" },
    app: { version: "2.0.41" }, location: { directory }, event: { subscribe: ({ signal }) => ({
      async *[Symbol.asyncIterator]() { await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true })) }
    }) } })
  const denied = await setup(ctx("/a"), async () => ({ ...identity(), cwd: "/fixture" }))
  denied(); assert.equal(globalThis[Symbol.for("downops.stalker.direct.v1")], undefined)
  const one = await setup(ctx("/a"), async () => identity()), two = await setup(ctx("/b"), async () => identity(7001))
  const shared = globalThis[Symbol.for("downops.stalker.direct.v1")]
  assert.equal(shared.owners.size, 2); one(); one(); assert.equal(shared.owners.size, 1)
  two(); assert.equal(globalThis[Symbol.for("downops.stalker.direct.v1")], undefined)
})
