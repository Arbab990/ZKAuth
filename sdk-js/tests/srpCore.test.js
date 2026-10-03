import { readFileSync } from "node:fs"
import { describe, expect, it, vi } from "vitest"
import {
  N,
  InvalidEphemeralError,
  computeClientProof,
  computeClientSession,
  computeServerProof,
  computeVerifier,
  generateClientEphemeral,
  generateSalt,
} from "../src/srpCore.js"

const username = "testvector-user"
const password = "testvector-password"
const saltHex = "00010203040506070001020304050607"
const expectedVerifierHex =
  "7e34eaea7940c860ff3aa1339abb9c435a1c190e4b32722d1f56eebe69c81521a3469d306a7b447749d4753fbbfa630efc262fee7a4b5a0bca77eb76898b35327ff85edfc88491dfe5df8f1ea2cda51704f99abb68030be01b9b9d719ee435df9d7ffbcb283594c2ac4ef175a5a3765128d19ea8e864fc85efbfcef9b134d1002217dc0a0b8474ecd25d522e2a4642b5f0a44f573bcd0d722f281d4958f9674387631061cbfaa91eb157b029f4130007ad26a0d75232397b0c24d09998f1dff3bce238bb3930363f19f7d67508846c2f38483af2e9965dfa8d5f1ede082b00ac4f7f902d5edc7398cf081b679a2496954cc6d28469e11cc81954e9397c743061"
const B =
  "5a8d1527f49a4b8d0e32a3d57cbd5a613cad15e5305668db94cea657e6e45630c84876d462d6d64b0e9182d2d1e8e3f893cbc217109b6a6147dbaebe81cd00e6f975123497b8b63e3d82ca32213d13211b7e543fd3c8699cfc729e86a1d19d7ed8fe0e32415546a4c49c195e3ea7f48b96a13d8acc9dbab722bbb91d8c0598891a0b01498549074bf21f3f9909696e73756ba3ba78aa06926e47c6ef88f92b0dc2ea7d32923b235030a2cb6c8bd34c3c5f3869c8bf7810e54150845f52e1a0256670d6a138c3338e5cd29e39a5b1059a3d3ddb49b4ee68f9bccb5bac5ada5e16dbf5d8caf1cbb73a260eb17b8e8a3c3a0ad6eaa1728529d8966033d8790e3200"
const width = Math.ceil(N.toString(2).length / 8) * 2
const padInt = (value) => value.toString(16).padStart(width, "0")
const A = padInt(64n)
const a = padInt(6n)
const paddedDigest = (tail) => "0".repeat(width - tail.length) + tail
const expectedK = paddedDigest(
  "24f42a7bab67af9030ea83ea539e716bffff1420f3707717816f0a82c5a8f83c",
)
const expectedM1 = paddedDigest(
  "ab1702b1c027e00796dd44119edbebe2ccb6a21abb7dd85485a473a3147034f9",
)
const expectedM2 = paddedDigest(
  "ef83e4b01db67f96e6c45d3b4b699889883d850e0b641e89d423f2e398633f0",
)

describe("SRP client test vectors", () => {
  it("computes the backend verifier vector exactly", async () => {
    await expect(computeVerifier(username, password, saltHex)).resolves.toBe(
      expectedVerifierHex,
    )
  })

  it("computes the backend session key vector exactly", async () => {
    const result = await computeClientSession(username, password, saltHex, A, a, B)
    expect(result.K).toBe(expectedK)
  })

  it("computes the client proof vector exactly", async () => {
    await expect(computeClientProof(A, B, expectedK)).resolves.toBe(expectedM1)
  })

  it("computes the server proof vector exactly", async () => {
    await expect(computeServerProof(A, expectedM1, expectedK)).resolves.toBe(
      expectedM2,
    )
  })

  it("rejects a malicious server B congruent to zero", async () => {
    await expect(
      computeClientSession(username, password, saltHex, A, a, "00"),
    ).rejects.toBeInstanceOf(InvalidEphemeralError)
  })

  it("matches the backend N constant and has a 2048-bit width", () => {
    const source = readFileSync(
      new URL("../../backend/app/core/srp_core.py", import.meta.url),
      "utf8",
    )
    const match = source.match(/N = int\(\s*"""([\s\S]*?)"""/)
    expect(match).not.toBeNull()
    const backendNHex = match[1].replace(/\s/g, "")
    expect(N).toBe(BigInt("0x" + backendNHex))
    expect(N.toString(2).length).toBe(2048)
  })

  it("rejects B equal to N and B equal to N plus one", async () => {
    await expect(
      computeClientSession(username, password, saltHex, A, a, padInt(N)),
    ).rejects.toBeInstanceOf(InvalidEphemeralError)
    await expect(
      computeClientSession(username, password, saltHex, A, a, padInt(N + 1n)),
    ).rejects.toBeInstanceOf(InvalidEphemeralError)
  })

  it("guards salt and ephemeral generation when Web Crypto is unavailable", () => {
    const message =
      "Web Crypto (crypto.subtle) is unavailable. ZKAuth requires a secure context: HTTPS or localhost."
    vi.stubGlobal("crypto", {
      getRandomValues: (array) => array.fill(1),
    })
    try {
      expect(() => generateSalt()).toThrowError(message)
      expect(() => generateClientEphemeral()).toThrowError(message)
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
