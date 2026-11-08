import { open, readlink } from "node:fs/promises"

const CORE = "/usr/local/bin/opencode"
const VAULT = "/opt/hashicorp/vault/2.1.2/vault"
const PROFILE = "/etc/vault-agent/native-opencode/config/agent.hcl"
const same = (actual, expected) => Array.isArray(actual) && actual.length === expected.length &&
  actual.every((value, index) => value === expected[index])

// A managed-process/accidental-fixture guard, NOT a same-UID security sandbox.
// PID is used only to locate the immediate parent, never as a persistent identity.
export function isManagedServer(identity) {
  return Boolean(identity && Number.isInteger(identity.pid) && identity.pid > 1 &&
    Number.isInteger(identity.ppid) && identity.ppid > 1 && identity.ppid !== identity.pid &&
    identity.uid === 100 && identity.euid === 100 && identity.home === "/var/lib/opencode" &&
    identity.cwd === "/srv/opencode" && identity.exe === CORE &&
    same(identity.argv, [CORE, "serve", "--hostname", "0.0.0.0", "--port", "4096"]) &&
    identity.parent?.exe === VAULT && same(identity.parent?.uids, [100, 100, 100, 100]) &&
    same(identity.parent?.argv, [VAULT, "agent", `-config=${PROFILE}`]))
}

async function boundedText(path) {
  const file = await open(path, "r")
  try {
    const buffer = Buffer.alloc(8193)
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0)
    if (bytesRead > 8192) throw new Error("identity_metadata_limit")
    return buffer.subarray(0, bytesRead).toString("utf8")
  } finally { await file.close() }
}

// No environment dump, HCL content read, SDK internals, process spawn or network.
// Missing/inaccessible metadata returns no identity and setup fails closed.
export async function readManagedIdentity(runtime = process, io = { boundedText, readlink }) {
  try {
    const ppid = runtime.ppid
    const [exe, command, parentExe, parentCommand, parentStatus] = await Promise.all([
      io.readlink("/proc/self/exe"), io.boundedText("/proc/self/cmdline"), io.readlink(`/proc/${ppid}/exe`),
      io.boundedText(`/proc/${ppid}/cmdline`), io.boundedText(`/proc/${ppid}/status`),
    ])
    if (runtime.ppid !== ppid) return undefined
    const uids = parentStatus.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m)
    return { pid: runtime.pid, ppid, uid: runtime.getuid(), euid: runtime.geteuid(),
      // Compiled Bun may include a virtual JS entrypoint in process.argv.
      // Match the real OS invocation, not that runtime compatibility array.
      home: runtime.env.HOME, cwd: runtime.cwd(), exe, argv: command.replace(/\0$/, "").split("\0"),
      parent: { exe: parentExe, argv: parentCommand.replace(/\0$/, "").split("\0"),
        uids: uids?.slice(1).map(Number) } }
  } catch { return undefined }
}
