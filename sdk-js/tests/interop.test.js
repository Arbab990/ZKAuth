import { beforeAll, afterAll, describe, expect, it } from "vitest"
import axios from "axios"
import { spawn } from "node:child_process"
import { setTimeout as delay } from "node:timers/promises"
import { fileURLToPath } from "node:url"

import {
  LoginFailedError,
  fetchPublicKey,
  login,
  register,
  verifyToken,
} from "../src/client.js"

const serverScript = fileURLToPath(new URL("./run_test_server.py", import.meta.url))
let serverProcess
let serverStderr = ""
let serverSpawnError
let userId
let username
let password
const baseUrl = "http://127.0.0.1:5099"

beforeAll(async () => {
  const python = process.env.ZKAUTH_TEST_PYTHON || "python3"
  serverProcess = spawn(python, [serverScript], { stdio: ["ignore", "ignore", "pipe"] })
  serverProcess.on("error", (error) => {
    serverSpawnError = error
  })
  serverProcess.stderr.setEncoding("utf8")
  serverProcess.stderr.on("data", (chunk) => {
    serverStderr += chunk
  })

  const deadline = Date.now() + 10000
  let isReady = false
  while (Date.now() < deadline) {
    if (serverSpawnError) {
      throw new Error("Could not start Python interop server: " + serverSpawnError.message)
    }
    if (serverProcess.exitCode !== null) {
      throw new Error("Python interop server exited early. " + serverStderr)
    }
    try {
      const response = await axios.get(baseUrl + "/health", { timeout: 500 })
      if (response.status === 200) {
        isReady = true
        break
      }
    } catch {
      await delay(200)
    }
  }
  if (!isReady) {
    if (serverProcess.pid) serverProcess.kill()
    throw new Error("Python interop server did not become ready. " + serverStderr)
  }

  username = "js-interop-user"
  password = "js-interop-correct-password"
  userId = await register(baseUrl, username, password)
  await register(baseUrl, "js-interop-wrong-password-user", "right-password")
}, 20000)

afterAll(async () => {
  if (serverProcess?.pid && serverProcess.exitCode === null) {
    serverProcess.kill()
    await Promise.race([new Promise((resolve) => serverProcess.once("exit", resolve)), delay(3000)])
  }
})

describe("JavaScript to Python live interop", () => {
  it("register returns a user_id", () => {
    expect(userId).toEqual(expect.any(String))
    expect(userId.length).toBeGreaterThan(0)
  })

  it("login with the correct password returns a token", async () => {
    const result = await login(baseUrl, username, password)
    expect(result.token).toEqual(expect.any(String))
    expect(result.token.length).toBeGreaterThan(0)
  })

  it("fetches the public key and verifies the backend-issued token", async () => {
    const result = await login(baseUrl, username, password)
    const publicKey = await fetchPublicKey(baseUrl)
    const claims = await verifyToken(result.token, publicKey)
    expect(claims.sub).toBe(userId)
    expect(claims.username).toBe(username)
  })

  it("wrong password rejects with LoginFailedError", async () => {
    await expect(
      login(baseUrl, "js-interop-wrong-password-user", "wrong-password"),
    ).rejects.toBeInstanceOf(LoginFailedError)
  })
})
