import axios from "axios"
import { importSPKI, jwtVerify, errors as joseErrors } from "jose"
import {
  InvalidEphemeralError,
  computeClientProof,
  computeClientSession,
  computeServerProof,
  generateClientEphemeral,
  generateSalt,
  computeVerifier,
} from "./srpCore.js"

const importedPublicKeys = new Map()

export class RegistrationError extends Error {
  constructor(message = "registration failed") {
    super(message)
    this.name = "RegistrationError"
  }
}

export class LoginFailedError extends Error {
  constructor(message = "invalid credentials") {
    super(message)
    this.name = "LoginFailedError"
  }
}

export class RateLimitError extends Error {
  constructor(message = "too many login attempts") {
    super(message)
    this.name = "RateLimitError"
  }
}

export class ServerUnavailableError extends Error {
  constructor(message = "authentication service unavailable") {
    super(message)
    this.name = "ServerUnavailableError"
  }
}

export class ServerProofMismatchError extends Error {
  constructor(message = "server proof did not match") {
    super(message)
    this.name = "ServerProofMismatchError"
  }
}

export class InvalidTokenError extends Error {
  constructor(message = "token is malformed or invalid") {
    super(message)
    this.name = "InvalidTokenError"
  }
}

export class TokenExpiredError extends InvalidTokenError {
  constructor(message = "token has expired") {
    super(message)
    this.name = "TokenExpiredError"
  }
}

export class TokenSignatureError extends InvalidTokenError {
  constructor(message = "token signature is invalid") {
    super(message)
    this.name = "TokenSignatureError"
  }
}

function responseErrorMessage(error, fallback) {
  const message = error?.response?.data?.error
  return typeof message === "string" && message ? message : fallback
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false
  let difference = left.length ^ right.length
  const length = Math.max(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0)
  }
  return difference === 0
}

function classifyLoginHttpError(status, phase) {
  if (status === 429) throw new RateLimitError()
  if (phase === "verify" && status === 401) {
    throw new LoginFailedError("invalid credentials")
  }
  throw new ServerUnavailableError()
}

async function loginPost(url, body, phase) {
  let response
  try {
    response = await axios.post(url, body)
  } catch (error) {
    if (!axios.isAxiosError(error)) throw error
    classifyLoginHttpError(error.response?.status, phase)
  }

  if (!response || response.status !== 200) {
    classifyLoginHttpError(response?.status, phase)
  }
  return response.data
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0
}

export async function register(baseUrl, username, password) {
  const salt = generateSalt()
  const verifier = await computeVerifier(username, password, salt)
  try {
    const response = await axios.post(baseUrl.replace(/\/$/, "") + "/api/register", {
      username,
      salt,
      verifier,
    })
    const data = response.data
    if (typeof data?.user_id !== "string" || !data.user_id) {
      throw new RegistrationError("registration response was malformed")
    }
    return data.user_id
  } catch (error) {
    if (error instanceof RegistrationError) throw error
    throw new RegistrationError(responseErrorMessage(error, "registration failed"))
  }
}

export async function login(baseUrl, username, password) {
  const base = baseUrl.replace(/\/$/, "")
  const init = await loginPost(base + "/api/login/init", { username }, "init")
  if (
    !init ||
    !isNonEmptyString(init.session_id) ||
    !isNonEmptyString(init.salt) ||
    !isNonEmptyString(init.server_public_ephemeral)
  ) {
    throw new ServerUnavailableError()
  }

  const ephemeral = generateClientEphemeral()
  let clientSession
  try {
    clientSession = await computeClientSession(
      username,
      password,
      init.salt,
      ephemeral.A,
      ephemeral.a,
      init.server_public_ephemeral,
    )
  } catch (error) {
    if (error instanceof InvalidEphemeralError) {
      throw new ServerProofMismatchError("server sent an invalid SRP ephemeral value")
    }
    throw error
  }

  const clientProof = await computeClientProof(
    ephemeral.A,
    init.server_public_ephemeral,
    clientSession.K,
  )
  const result = await loginPost(
    base + "/api/login/verify",
    {
      session_id: init.session_id,
      client_public_ephemeral: ephemeral.A,
      client_proof: clientProof,
    },
    "verify",
  )

  if (
    !result ||
    !isNonEmptyString(result.server_proof) ||
    !isNonEmptyString(result.token)
  ) {
    throw new ServerUnavailableError()
  }

  const expectedProof = await computeServerProof(
    ephemeral.A,
    clientProof,
    clientSession.K,
  )
  if (!constantTimeEqual(expectedProof, result.server_proof)) {
    throw new ServerProofMismatchError()
  }
  return { token: result.token }
}

function getImportedPublicKey(publicKeyPem) {
  let keyPromise = importedPublicKeys.get(publicKeyPem)
  if (!keyPromise) {
    keyPromise = Promise.resolve().then(() => importSPKI(publicKeyPem, "EdDSA"))
    importedPublicKeys.set(publicKeyPem, keyPromise)
    keyPromise.catch(() => {
      if (importedPublicKeys.get(publicKeyPem) === keyPromise) {
        importedPublicKeys.delete(publicKeyPem)
      }
    })
  }
  return keyPromise
}

export async function verifyToken(token, publicKeyPem) {
  try {
    const publicKey = await getImportedPublicKey(publicKeyPem)
    const result = await jwtVerify(token, publicKey, {
      algorithms: ["EdDSA"],
      requiredClaims: ["exp", "iat"],
    })
    return result.payload
  } catch (error) {
    if (error instanceof joseErrors.JWTExpired) {
      throw new TokenExpiredError(error.message)
    }
    if (error instanceof joseErrors.JWSSignatureVerificationFailed) {
      throw new TokenSignatureError(error.message)
    }
    throw new InvalidTokenError(error instanceof Error ? error.message : undefined)
  }
}

export async function fetchPublicKey(baseUrl) {
  try {
    const response = await axios.get(baseUrl.replace(/\/$/, "") + "/api/public-key")
    const publicKey = response.data?.public_key_pem
    if (typeof publicKey !== "string" || !publicKey) {
      throw new Error("public-key response was malformed")
    }
    return publicKey
  } catch (error) {
    const message = error?.response?.data?.error
    throw new Error(
      typeof message === "string" && message
        ? message
        : error instanceof Error
          ? error.message
          : "could not fetch public key",
    )
  }
}
