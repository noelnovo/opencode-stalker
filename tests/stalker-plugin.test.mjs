import test from "node:test"
import assert from "node:assert/strict"
import { generateKeyPairSync, verify } from "node:crypto"
import { mkdtemp, writeFile, chmod, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { setup, Queue, DirectSender, message, eventID, readCredentials, selectDevices } from "../plugin/index.mjs"
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
  const payload = message({ token: "SYNTHETIC_DEVICE_TOKEN_123" }, eventID("/a", "frm_one"), 400000, 1000)
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
const devices = [{ schema: 1, device_id: "synthetic-installation", enabled: true, package: "com.example.dev", token: "SYNTHETIC_DEVICE_TOKEN_123" }]
// Deliberately fake: real installation topics never belong in source or logs.
const topic = "stalker_" + "A".repeat(43)
const topicDevice = { ...devices[0], topic }
test("topic and legacy token validation enforce schema, package, identifiers and bounds", () => {
  assert.deepEqual(selectDevices([topicDevice]), [{ topic }])
  assert.deepEqual(selectDevices(devices), [{ token: devices[0].token }])
  for (const invalid of [null, 1, "", "stalker_" + "A".repeat(42), "stalker_" + "A".repeat(44),
    "/topics/" + topic, "stalker_" + "=".repeat(43), "stalker_" + "é".repeat(43), topic + "\n"]) {
    assert.deepEqual(selectDevices([{ ...topicDevice, topic: invalid }]), [])
  }
  assert.deepEqual(selectDevices([{ ...topicDevice, topic: "stalker_" + "_-a".repeat(14) + "Z" }]).length, 1)
  for (const token of [null, 1, "", "x".repeat(19), "x".repeat(4097), "x".repeat(20) + "\n", "x".repeat(20) + " "]) {
    assert.deepEqual(selectDevices([{ ...devices[0], token }]), [])
  }
  for (const length of [20, 4096]) assert.equal(selectDevices([{ ...devices[0], token: "x".repeat(length) }]).length, 1)
  for (const variant of [{ schema: "1" }, { schema: 2 }, { package: "other.package" },
    { enabled: false }, { enabled: "true" }, { enabled: undefined }, { device_id: "" },
    { device_id: "x".repeat(129) }, { device_id: "invalid/id" }, { device_id: undefined }]) {
    assert.deepEqual(selectDevices([{ ...topicDevice, ...variant }]), [])
  }
  assert.deepEqual(selectDevices([null, false, "invalid"]), [])
  assert.equal(selectDevices(Array.from({ length: 100 }, (_, n) => ({ ...topicDevice, device_id: "fake_" + n }))).length, 1)
  for (const input of [{}, null, Array(101).fill(topicDevice)]) assert.throws(() => selectDevices(input), /devices_invalid/)
})
test("one target per device prefers topic independent of order and never falls back from an invalid topic", () => {
  for (const records of [[devices[0], topicDevice], [topicDevice, devices[0]], [topicDevice, topicDevice]]) {
    assert.deepEqual(selectDevices(records), [{ topic }])
  }
  assert.deepEqual(selectDevices([devices[0], { ...topicDevice, topic: "invalid" }]), [])
  assert.deepEqual(selectDevices([topicDevice, { ...topicDevice, topic: "stalker_" + "B".repeat(43) }]), [])
  assert.deepEqual(selectDevices([devices[0], { ...devices[0], token: "SYNTHETIC_DIFFERENT_TOKEN" }]), [])
  for (const record of [devices[0], topicDevice]) {
    assert.deepEqual(selectDevices([topicDevice, { ...record, enabled: false }]), [])
  }
  assert.deepEqual(selectDevices([topicDevice, { ...devices[0], device_id: "other-installation" }]),
    [{ topic }, { token: devices[0].token }])
})
test("topic payload is generic, data-only, package-restricted and TTL bounded", () => {
  for (const [expires, now, ttl] of [[400000, 1000, "300s"], [999, 1000, "0s"], [2999, 1000, "1s"]]) {
    const payload = message({ topic, text: "PRIVATE", command: "PRIVATE" }, "opaque_fake_id", expires, now)
    assert.deepEqual(Object.keys(payload.message).sort(), ["android", "data", "topic"])
    assert.deepEqual(payload.message.data, { schema: "1", kind: "question", event_id: "opaque_fake_id" })
    assert.deepEqual(payload.message.android, { priority: "HIGH", ttl, restricted_package_name: "com.example.dev" })
    assert.equal(JSON.stringify(payload).includes("PRIVATE"), false)
  }
  for (const target of [{ topic, token: devices[0].token }, { topic: "invalid" }, { token: "invalid" }, null]) {
    assert.throws(() => message(target, "opaque_fake_id", 1000), /message_invalid/)
  }
  for (const id of ["PRIVATE QUESTION TEXT", "x".repeat(129), null]) {
    assert.throws(() => message({ topic }, id, 1000), /message_invalid/)
  }
})
test("sender posts one topic per installation plus legacy other device without leaking routes or Google error text", async () => {
  const sent = [], receipts = [], logs = []
  const original = console.info
  console.info = (...args) => logs.push(args.join(" "))
  try {
    const sender = new DirectSender(async () => ({ account, devices: [devices[0], topicDevice,
      { ...devices[0], device_id: "other-installation" }, { ...topicDevice, device_id: "disabled", enabled: false }] }),
    async (url, options) => {
      if (url.includes("oauth2")) return Response.json({ access_token: "SYNTHETIC_ACCESS_TOKEN" })
      sent.push(JSON.parse(options.body).message)
      return Response.json({ name: "PRIVATE_RESPONSE_TEXT" })
    })
    const q = new Queue(sender, (receipt) => receipts.push(receipt))
    q.accept(created(), "/a", 1)
    q.pending.values().next().value.due = Date.now() - 1
    await q.tick()
    assert.equal(sent.length, 2)
    assert.equal(sent[0].topic, topic); assert.equal(Object.hasOwn(sent[0], "token"), false)
    assert.equal(sent[1].token, devices[0].token); assert.equal(Object.hasOwn(sent[1], "topic"), false)
    assert.equal(receipts.length, 1)
    assert.deepEqual(Object.keys(receipts[0]).sort(), ["event_id", "status", "timestamp"])
    sender.fetcher = async () => Response.json({ error: { message: "PRIVATE_ERROR_TEXT " + topic } }, { status: 500 })
    assert.equal(await sender.send({ id: "fake_id", expires: Date.now() + 300000 }, new AbortController().signal), 500)
    const output = JSON.stringify({ receipts, logs })
    for (const secret of [topic, devices[0].token, "PRIVATE", "SYNTHETIC_ACCESS_TOKEN"]) assert.equal(output.includes(secret), false)
    q.close()
  } finally { console.info = original }
})
test("UNREGISTERED quarantine remains token-only and cannot poison a stable topic", async () => {
  let records = devices, calls = 0
  const sender = new DirectSender(async () => ({ account, devices: records }), async (url) => {
    if (url.includes("oauth2")) return Response.json({ access_token: "SYNTHETIC_ACCESS_TOKEN" })
    calls++
    return Response.json({ error: { details: [{ errorCode: "UNREGISTERED" }] } }, { status: 404 })
  })
  const send = () => sender.send({ id: "fake_id", expires: Date.now() + 300000 }, new AbortController().signal)
  assert.equal(await send(), 404); assert.equal(await send(), 204); assert.equal(calls, 1)
  records = [topicDevice]
  assert.equal(await send(), 404); assert.equal(await send(), 404); assert.equal(calls, 3)
  assert.equal(sender.disabled.size, 1)
})
test("expired, aborted and disabled topic work cannot publish an FCM message", async () => {
  let calls = 0, records = [topicDevice]
  const sender = new DirectSender(async () => ({ account, devices: records }), async (url) => {
    if (url.includes("oauth2")) return Response.json({ access_token: "SYNTHETIC_ACCESS_TOKEN" })
    calls++; return Response.json({})
  })
  assert.equal(await sender.send({ id: "fake_id", expires: Date.now() - 1 }, new AbortController().signal), 410)
  const controller = new AbortController(); controller.abort()
  assert.equal(await sender.send({ id: "fake_id", expires: Date.now() + 300000 }, controller.signal), 410)
  records = [{ ...topicDevice, enabled: false }]
  assert.equal(await sender.send({ id: "fake_id", expires: Date.now() + 300000 }, new AbortController().signal), 204)
  assert.equal(calls, 0)
})
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
      devices: { DEVICES_JSON: JSON.stringify([...devices, { ...devices[0], device_id: "disabled-installation", enabled: false }]) } }), { mode: 0o600 })
    assert.equal(selectDevices((await readCredentials(path)).devices).length, 1)
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
