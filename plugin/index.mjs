import { createHash, sign } from "node:crypto"
import { lstat, readFile } from "node:fs/promises"
import { isManagedServer, readManagedIdentity } from "./identity.mjs"

const TYPES = new Set(["form.created", "form.replied", "form.cancelled"])
const PACKAGE = "com.example.dev"
const TTL = 300000
const KEY = Symbol.for("downops.stalker.direct.v1")
const hash = (value) => createHash("sha256").update(value).digest("hex")
export const eventID = (directory, formID) => hash(JSON.stringify(["stalker-direct-v1", directory, formID]))

// Google responses are never logged; cap bodies as well as network duration.
async function request(url, options, signal, fetcher) {
  const response = await fetcher(url, { ...options,
    signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]), redirect: "error" })
  const reader = response.body?.getReader()
  const chunks = []
  let size = 0
  if (reader) {
    try {
      for (;;) {
        const part = await reader.read()
        if (part.done) break
        size += part.value.length
        if (size > 65536) throw new Error("response_limit")
        chunks.push(Buffer.from(part.value))
      }
    } finally { await reader.cancel().catch(() => {}) }
  }
  let body = {}
  try { body = JSON.parse(Buffer.concat(chunks).toString()) } catch {}
  return { status: response.status, body }
}

export async function readCredentials(path) {
  const info = await lstat(path)
  if (!info.isFile() || info.nlink !== 1 || info.uid !== process.getuid() ||
      (info.mode & 0o777) !== 0o600 || info.size > 131072) throw new Error("credential_file_invalid")
  const value = JSON.parse(await readFile(path, "utf8"))
  const account = JSON.parse(value.fcm.SERVICE_ACCOUNT_JSON)
  const devices = JSON.parse(value.devices.DEVICES_JSON)
  if (value.fcm.PROJECT_ID !== "example-project" || account.project_id !== "example-project" ||
      account.type !== "service_account" || typeof account.client_email !== "string" ||
      typeof account.private_key !== "string" || account.private_key.length > 16384 ||
      !Array.isArray(devices) || devices.length > 100) throw new Error("credentials_invalid")
  return { account, devices: devices.filter((d) => d.enabled === true && d.schema === 1 &&
    d.package === PACKAGE && typeof d.token === "string" && d.token.length >= 20 && d.token.length <= 4096) }
}

export function message(token, id, expires, now = Date.now()) {
  return { message: { token, data: { schema: "1", kind: "question", event_id: id },
    android: { priority: "HIGH", ttl: `${Math.max(0, Math.min(300, Math.floor((expires - now) / 1000)))}s`,
      restricted_package_name: PACKAGE } } }
}

export class DirectSender {
  constructor(credentials, fetcher = fetch) {
    this.credentials = credentials
    this.fetcher = fetcher
    this.token = undefined
    this.disabled = new Set()
  }
  async send(item, signal) {
    const { account, devices } = await this.credentials()
    const fingerprint = hash(account.private_key)
    if (!this.token || this.token.fingerprint !== fingerprint || this.token.expires <= Date.now()) {
      const encode = (v) => Buffer.from(JSON.stringify(v)).toString("base64url")
      const now = Math.floor(Date.now() / 1000)
      const unsigned = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ iss: account.client_email,
        scope: "https://www.googleapis.com/auth/firebase.messaging", aud: "https://oauth2.googleapis.com/token",
        iat: now, exp: now + 3600 })}`
      const assertion = unsigned + "." + sign("RSA-SHA256", Buffer.from(unsigned), account.private_key).toString("base64url")
      const result = await request("https://oauth2.googleapis.com/token", { method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }) }, signal, this.fetcher)
      if (result.status !== 200) return result.status
      if (typeof result.body.access_token !== "string") return 502
      this.token = { value: result.body.access_token, fingerprint,
        expires: Date.now() + Math.min(3500, Number(result.body.expires_in) || 3000) * 1000 }
    }
    let status = 204
    for (const device of devices) {
      if (signal.aborted || item.expires <= Date.now()) return 410
      const key = hash(device.token)
      if (this.disabled.has(key)) continue
      const result = await request("https://fcm.googleapis.com/v1/projects/example-project/messages:send", {
        method: "POST", headers: { Authorization: `Bearer ${this.token.value}`, "Content-Type": "application/json" },
        body: JSON.stringify(message(device.token, item.id, item.expires)) }, signal, this.fetcher)
      status = result.status
      if (status === 401) this.token = undefined
      if (result.body.error?.details?.some((d) => d.errorCode === "UNREGISTERED")) {
        if (this.disabled.size >= 100) this.disabled.delete(this.disabled.values().next().value)
        this.disabled.add(key)
      }
      if (status !== 200) return status
    }
    return status
  }
}

// Shared across Location plugin instances, including duplicated global events.
// Retain only hashes, deadlines and owner handles, never form text/session IDs.
export class Queue {
  constructor(sender, report = () => {}, now = Date.now) {
    this.sender = sender
    this.report = report
    this.now = now
    this.pending = new Map()
    this.seen = new Map()
    this.running = undefined
  }
  expire() {
    const now = this.now()
    for (const [id, expiry] of this.seen) if (expiry <= now) this.seen.delete(id)
    for (const [id, item] of this.pending) if (item.expires <= now) this.drop(id)
  }
  remember(id) {
    if (this.seen.size >= 512) this.seen.delete(this.seen.keys().next().value)
    this.seen.set(id, this.now() + TTL)
  }
  drop(id) {
    this.pending.get(id)?.controller.abort()
    this.pending.delete(id)
  }
  accept(event, directory, owner) {
    if (!event || !TYPES.has(event.type)) return false //2.0.41 ignores types options.
    const origin = event.location?.directory ?? "global"
    if (origin !== "global" && origin !== directory) return false
    const form = event.data?.form
    const fid = event.type === "form.created" ? form?.id : event.data?.id
    if (typeof fid !== "string" || !/^frm_[A-Za-z0-9_-]{1,252}$/.test(fid) || origin.length > 4096) return false
    const id = eventID(origin, fid)
    this.expire()
    if (event.type !== "form.created") { this.drop(id); this.remember(id); return true }
    if (form.metadata?.kind !== "question" || typeof form.sessionID !== "string" ||
        !/^ses_[A-Za-z0-9_-]{1,252}$/.test(form.sessionID)) return false
    const existing = this.pending.get(id)
    if (existing) { existing.owners.add(owner); return false }
    if (this.seen.has(id)) return false
    this.remember(id)
    if (this.pending.size >= 64) return false //Drop newest, no replay.
    this.pending.set(id, { id, expires: this.now() + TTL, due: this.now() + 250,
      owners: new Set([owner]), controller: new AbortController(), attempts: 0 })
    return true
  }
  detach(owner) {
    for (const [id, item] of this.pending) {
      item.owners.delete(owner)
      if (!item.owners.size) this.drop(id)
    }
  }
  async tick() {
    this.expire()
    if (this.running) return
    const item = [...this.pending.values()].find((p) => p.due <= this.now())
    if (!item) return
    this.running = item
    item.attempts++
    try {
      const status = await this.sender.send(item, item.controller.signal)
      if (item.controller.signal.aborted) return
      this.report({ event_id: item.id, timestamp: new Date().toISOString(), status })
      if ((status === 401 || status === 429 || status >= 500) && item.attempts < 2) item.due = this.now() + 500
      else this.drop(item.id)
    } catch {
      if (!item.controller.signal.aborted && item.attempts < 2) item.due = this.now() + 500
      else this.drop(item.id)
    } finally { this.running = undefined }
  }
  close() { for (const id of this.pending.keys()) this.drop(id) }
}

// Tests may inject the metadata reader as a function, never through config options.
export async function setup(ctx, identityReader = readManagedIdentity) {
    const options = ctx.options ?? {}
    if (!isManagedServer(await identityReader())) return () => {}
    if (ctx.app.version !== "2.0.41") throw new Error("stalker_unsupported_version")
    if (typeof options.credentialFile !== "string" || !options.credentialFile.startsWith("/"))
      throw new Error("stalker_unconfigured")
    let shared = globalThis[KEY]
    if (!shared) {
      const queue = new Queue(new DirectSender(() => readCredentials(options.credentialFile)),
        (receipt) => console.info(JSON.stringify({ stalker: "direct-fcm", ...receipt })))
      shared = { queue, owners: new Set(), timer: setInterval(() => void queue.tick(), 100) }
      globalThis[KEY] = shared
    }
    const owner = Symbol()
    shared.owners.add(owner)
    const controller = new AbortController()
    let closed = false
    const cleanup = () => {
      if (closed) return
      closed = true
      controller.abort()
      shared.queue.detach(owner)
      shared.owners.delete(owner)
      if (!shared.owners.size) {
        clearInterval(shared.timer)
        shared.queue.close()
        delete globalThis[KEY]
      }
    }
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
          if (closed) break
          shared.queue.accept(event, ctx.location.directory, owner)
        }
      } catch {} finally { cleanup() }
    })()
    console.info(JSON.stringify({ stalker: "direct-fcm", state: "subscribed", version: "0.3.1", guard: "managed-v1", pid: process.pid }))
    return cleanup
}

export default { id: "downops.opencode-stalker", setup: (ctx) => setup(ctx) }
