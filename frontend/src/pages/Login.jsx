import { useState } from "react"
import {
  getBaseUrl,
  LoginFailedError,
  login,
  RateLimitError,
  ServerProofMismatchError,
  ServerUnavailableError,
  fetchPublicKey,
  verifyToken,
} from "../api/zkauth.js"

const inputClass =
  "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 shadow-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200"

function messageForError(error) {
  if (error instanceof LoginFailedError) {
    return "Incorrect username or password."
  }
  if (error instanceof RateLimitError) {
    return "Too many attempts — please wait a moment and try again."
  }
  if (error instanceof ServerUnavailableError) {
    return "Could not reach the server. Please try again shortly."
  }
  if (error instanceof ServerProofMismatchError) {
    return "The server's identity could not be verified. Login aborted for your safety."
  }

  return "Something went wrong. Please try again."
}

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setError("")
    setIsSubmitting(true)
    try {
      const result = await login(getBaseUrl(), username, password)
      const publicKey = await fetchPublicKey(getBaseUrl())
      const claims = await verifyToken(result.token, publicKey)
      // Keep bearer tokens in memory only; this demo intentionally avoids browser storage.
      onLoginSuccess({ token: result.token, claims })
    } catch (caught) {
      setError(messageForError(caught))
    } finally {
      setIsSubmitting(false)
      setPassword("")
    }
  }

  return (
    <section className="mx-auto w-full max-w-md rounded-xl bg-white p-6 shadow">
      <h2 className="text-xl font-semibold">Log in</h2>
      <p className="mt-1 text-sm text-slate-600">
        Prove your password without sending it to the server.
      </p>

      <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
        <label className="block text-sm font-medium text-slate-700">
          Username
          <input
            autoComplete="username"
            className={inputClass}
            onChange={(event) => setUsername(event.target.value)}
            required
            type="text"
            value={username}
          />
        </label>
        <label className="block text-sm font-medium text-slate-700">
          Password
          <input
            autoComplete="current-password"
            className={inputClass}
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
          />
        </label>
        <button
          className="w-full rounded-md bg-indigo-700 px-4 py-2 font-medium text-white hover:bg-indigo-800 disabled:cursor-wait disabled:opacity-60"
          disabled={isSubmitting}
          type="submit"
        >
          {isSubmitting ? "Signing in…" : "Login"}
        </button>
      </form>

      {error && (
        <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}
