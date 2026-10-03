import axios from "axios"
import { importSPKI, jwtVerify, errors as joseErrors } from "jose"
import {
  computeClientProof,
  computeClientSession,
  computeServerProof,
  generateClientEphemeral,
  generateSalt,
  computeVerifier,
} from "./srpCore.js"

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
  let init
  let A
  let clientProof
  let K
  let result
  try {
    init = (await axios.post(base + "/api/login/init", { username })).data
    const ephemeral = generateClientEphemeral()
    A = ephemeral.A
    const clientSession = await computeClientSession(
      username,
      password,
      init.salt,
      A,
      ephemeral.a,
      init.server_public_ephemeral,
    )
    K = clientSession.K
    clientProof = await computeClientProof(A, init.server_public_ephemeral, K)
    result = (await axios.post(base + "/api/login/verify", {
      session_id: init.session_id,
      client_public_ephemeral: A,
      client_proof: clientProof,
    })).data
  } catch {
    throw new LoginFailedError("invalid credentials")
  }

  const expectedProof = await computeServerProof(A, clientProof, K)
  if (!constantTimeEqual(expectedProof, result?.server_proof)) {
    throw new ServerProofMismatchError()
  }
  if (typeof result?.token !== "string" || !result.token) {
    throw new ServerProofMismatchError("server response did not include a token")
  }
  return { token: result.token }
}

export async function verifyToken(token, publicKeyPem) {
  try {
    const publicKey = await importSPKI(publicKeyPem, "EdDSA")
    const result = await jwtVerify(token, publicKey, { algorithms: ["EdDSA"] })
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
