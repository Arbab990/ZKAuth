// ZKAuth client-side SRP-6a, interoperable with backend/app/core/srp_core.py.
export const N = 0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73n
export const g = 2n
const BYTE_WIDTH = Math.ceil(N.toString(2).length / 8)
const HEX_WIDTH = BYTE_WIDTH * 2
const encoder = new TextEncoder()

export class InvalidEphemeralError extends Error {
  constructor(message = "Invalid SRP ephemeral value") {
    super(message)
    this.name = "InvalidEphemeralError"
  }
}

function bigIntToPaddedHex(value) {
  if (value < 0n || value >= (1n << BigInt(BYTE_WIDTH * 8))) {
    throw new RangeError("integer does not fit the SRP group width")
  }
  return value.toString(16).padStart(HEX_WIDTH, "0")
}

function paddedHexToBigInt(hex) {
  if (typeof hex !== "string" || !hex || !/^[0-9a-f]+$/i.test(hex)) {
    throw new TypeError("value must be a non-empty hexadecimal string")
  }
  if (hex.length > HEX_WIDTH) {
    throw new RangeError("value exceeds the SRP group width")
  }
  return BigInt("0x" + hex)
}

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new TypeError("hex string must contain complete bytes")
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")
}

function concatBytes(...arrays) {
  const result = new Uint8Array(arrays.reduce((size, array) => size + array.length, 0))
  let offset = 0
  for (const array of arrays) {
    result.set(array, offset)
    offset += array.length
  }
  return result
}

function padBigIntBytes(value) {
  return hexToBytes(bigIntToPaddedHex(value))
}

async function hashInt(bytes) {
  const digest = await sha256(bytes)
  return BigInt("0x" + bytesToHex(digest))
}

async function computeKMultiplier() {
  return hashInt(concatBytes(padBigIntBytes(N), padBigIntBytes(g)))
}

async function computeX(username, password, saltHex) {
  const saltBytes = hexToBytes(saltHex)
  if (saltBytes.length === 0) {
    throw new TypeError("saltHex must not be empty")
  }
  const inner = await sha256(encoder.encode(username + ":" + password))
  return hashInt(concatBytes(saltBytes, inner))
}

async function computeU(A, B) {
  const u = await hashInt(concatBytes(padBigIntBytes(A), padBigIntBytes(B)))
  if (u === 0n) {
    throw new InvalidEphemeralError("SRP scrambling parameter u must not be zero")
  }
  return u
}

function modPow(base, exponent, modulus) {
  let result = 1n
  base %= modulus
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus
    exponent >>= 1n
    base = (base * base) % modulus
  }
  return result
}

function randomBigIntBelow(limit) {
  const randomBytes = new Uint8Array(BYTE_WIDTH)
  globalThis.crypto.getRandomValues(randomBytes)
  return BigInt("0x" + bytesToHex(randomBytes)) % limit
}

export async function sha256(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes)
  return new Uint8Array(digest)
}

export function generateSalt() {
  const salt = new Uint8Array(16)
  globalThis.crypto.getRandomValues(salt)
  return bytesToHex(salt)
}

export async function computeVerifier(username, password, saltHex) {
  const x = await computeX(username, password, saltHex)
  return bigIntToPaddedHex(modPow(g, x, N))
}

export function generateClientEphemeral() {
  const a = randomBigIntBelow(N - 1n) + 1n
  return { A: bigIntToPaddedHex(modPow(g, a, N)), a: bigIntToPaddedHex(a) }
}

export async function computeClientSession(username, password, saltHex, AHex, aHex, BHex) {
  const A = paddedHexToBigInt(AHex)
  const a = paddedHexToBigInt(aHex)
  const B = paddedHexToBigInt(BHex)
  if (B % N === 0n) {
    throw new InvalidEphemeralError("B must not be congruent to zero modulo N")
  }

  const u = await computeU(A, B)
  const x = await computeX(username, password, saltHex)
  const k = await computeKMultiplier()
  const verifier = modPow(g, x, N)
  const base = ((B - k * verifier) % N + N) % N
  const S = modPow(base, a + u * x, N)
  const K = await hashInt(padBigIntBytes(S))
  return { K: bigIntToPaddedHex(K) }
}

export async function computeClientProof(AHex, BHex, KHex) {
  const A = paddedHexToBigInt(AHex)
  const B = paddedHexToBigInt(BHex)
  const K = paddedHexToBigInt(KHex)
  const digest = await hashInt(
    concatBytes(padBigIntBytes(A), padBigIntBytes(B), padBigIntBytes(K)),
  )
  return bigIntToPaddedHex(digest)
}

export async function computeServerProof(AHex, M1Hex, KHex) {
  const A = paddedHexToBigInt(AHex)
  const M1 = paddedHexToBigInt(M1Hex)
  const K = paddedHexToBigInt(KHex)
  const digest = await hashInt(
    concatBytes(padBigIntBytes(A), padBigIntBytes(M1), padBigIntBytes(K)),
  )
  return bigIntToPaddedHex(digest)
}
