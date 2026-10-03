import axios from "axios"
import {
  generateKeyPair,
  exportSPKI,
  SignJWT,
} from "jose"
import {
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest"
import {
  InvalidTokenError,
  LoginFailedError,
  RateLimitError,
  ServerProofMismatchError,
  ServerUnavailableError,
  TokenExpiredError,
  TokenSignatureError,
  fetchPublicKey,
  login,
  verifyToken,
} from "../src/client.js"

let signingKey
let otherSigningKey
let publicKeyPem

beforeAll(async () => {
  const firstPair = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  })
  const secondPair = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  })
  signingKey = firstPair.privateKey
  otherSigningKey = secondPair.privateKey
  publicKeyPem = await exportSPKI(firstPair.publicKey)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

async function signToken(privateKey, claims, options = {}) {
  let builder = new SignJWT(claims).setProtectedHeader({ alg: "EdDSA" })
  if (options.issuedAt) builder = builder.setIssuedAt()
  if (options.expiresAt !== undefined) builder = builder.setExpirationTime(options.expiresAt)
  return builder.sign(privateKey)
}

function axiosError(status) {
  return Object.assign(new Error("request failed"), {
    isAxiosError: true,
    response: { status, data: { error: "request failed" } },
  })
}

function networkError() {
  return Object.assign(new Error("network failure"), { isAxiosError: true })
}

function initResponse(serverPublicEphemeral = "01", dataOverrides = {}) {
  return {
    status: 200,
    data: {
      session_id: "test-session",
      salt: "000102030405060708090a0b0c0d0e0f",
      server_public_ephemeral: serverPublicEphemeral,
      ...dataOverrides,
    },
  }
}

function spyInitThenVerify(verifyOutcome) {
  const post = vi.spyOn(axios, "post")
  post.mockResolvedValueOnce(initResponse())
  if (verifyOutcome instanceof Error) {
    post.mockRejectedValueOnce(verifyOutcome)
  } else {
    post.mockResolvedValueOnce(verifyOutcome)
  }
  return post
}

describe("verifyToken claims and error normalization", () => {
  it("verifies a valid EdDSA token with exp and iat", async () => {
    const token = await signToken(
      signingKey,
      { sub: "user-1", username: "alice" },
      { issuedAt: true, expiresAt: "5m" },
    )
    await expect(verifyToken(token, publicKeyPem)).resolves.toMatchObject({
      sub: "user-1",
      username: "alice",
    })
  })

  it("rejects a token missing exp as InvalidTokenError, not TokenExpiredError", async () => {
    const token = await signToken(signingKey, { sub: "user-1" }, { issuedAt: true })
    const error = await verifyToken(token, publicKeyPem).then(
      () => null,
      (caught) => caught,
    )
    expect(error).toBeInstanceOf(InvalidTokenError)
    expect(error).not.toBeInstanceOf(TokenExpiredError)
  })

  it("rejects a token missing iat as InvalidTokenError", async () => {
    const token = await signToken(signingKey, { sub: "user-1" }, { expiresAt: "5m" })
    await expect(verifyToken(token, publicKeyPem)).rejects.toBeInstanceOf(
      InvalidTokenError,
    )
  })

  it("maps an expired token to TokenExpiredError", async () => {
    const token = await signToken(signingKey, { sub: "user-1" }, {
      issuedAt: true,
      expiresAt: Math.floor(Date.now() / 1000) - 60,
    })
    await expect(verifyToken(token, publicKeyPem)).rejects.toBeInstanceOf(
      TokenExpiredError,
    )
  })

  it("maps a token signed by another key to TokenSignatureError", async () => {
    const token = await signToken(
      otherSigningKey,
      { sub: "user-1" },
      { issuedAt: true, expiresAt: "5m" },
    )
    await expect(verifyToken(token, publicKeyPem)).rejects.toBeInstanceOf(
      TokenSignatureError,
    )
  })

  it("maps garbage token input to InvalidTokenError", async () => {
    await expect(verifyToken("garbage", publicKeyPem)).rejects.toBeInstanceOf(
      InvalidTokenError,
    )
  })
})

describe("login HTTP error classification", () => {
  it("maps a verify 401 to LoginFailedError", async () => {
    spyInitThenVerify(axiosError(401))
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      LoginFailedError,
    )
  })

  it("maps an init 429 to RateLimitError", async () => {
    vi.spyOn(axios, "post").mockRejectedValueOnce(axiosError(429))
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      RateLimitError,
    )
  })

  it("maps a verify 429 to RateLimitError", async () => {
    spyInitThenVerify(axiosError(429))
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      RateLimitError,
    )
  })

  it("maps a network error to ServerUnavailableError", async () => {
    vi.spyOn(axios, "post").mockRejectedValueOnce(networkError())
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      ServerUnavailableError,
    )
  })

  it("maps an HTTP 500 to ServerUnavailableError", async () => {
    vi.spyOn(axios, "post").mockRejectedValueOnce(axiosError(500))
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      ServerUnavailableError,
    )
  })

  it("maps a malformed init response to ServerUnavailableError", async () => {
    vi.spyOn(axios, "post").mockResolvedValueOnce({
      status: 200,
      data: { session_id: "test-session", server_public_ephemeral: "01" },
    })
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      ServerUnavailableError,
    )
  })

  it("maps a zero SRP server ephemeral to ServerProofMismatchError", async () => {
    vi.spyOn(axios, "post").mockResolvedValueOnce(
      initResponse("0".repeat(512)),
    )
    await expect(login("https://example.test", "alice", "password")).rejects.toMatchObject({
      name: "ServerProofMismatchError",
      message: "server sent an invalid SRP ephemeral value",
    })
  })

  it("rejects a token when the server proof is wrong", async () => {
    spyInitThenVerify({
      status: 200,
      data: { token: "must-not-be-returned", server_proof: "0".repeat(512) },
    })
    await expect(login("https://example.test", "alice", "password")).rejects.toBeInstanceOf(
      ServerProofMismatchError,
    )
  })

  it("propagates non-Axios errors unchanged", async () => {
    const unexpectedError = new TypeError("boom")
    vi.spyOn(axios, "post")
      .mockResolvedValueOnce(initResponse())
      .mockRejectedValueOnce(unexpectedError)
    await expect(
      login("http://127.0.0.1:1", "alice", "password"),
    ).rejects.toBe(unexpectedError)
  })

  it("fetches a valid public key with axios.get", async () => {
    vi.spyOn(axios, "get").mockResolvedValueOnce({
      data: { public_key_pem: publicKeyPem },
    })
    await expect(fetchPublicKey("https://example.test")).resolves.toBe(publicKeyPem)
  })
})
