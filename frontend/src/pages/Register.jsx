import { useState } from "react"
import {
  getBaseUrl,
  register,
  RegistrationError,
} from "../api/zkauth.js"

const inputClass =
  "mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 shadow-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200"

export default function Register({ onGoToLogin }) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [userId, setUserId] = useState(null)
  const [error, setError] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setError("")
    setUserId(null)
    setIsSubmitting(true)
    try {
      const id = await register(getBaseUrl(), username, password)
      setUserId(id)
      setPassword("")
    } catch (caught) {
      setError(
        caught instanceof RegistrationError
          ? caught.message
          : "Something went wrong. Please try again.",
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <section className="mx-auto w-full max-w-md rounded-xl bg-white p-6 shadow">
      <h2 className="text-xl font-semibold">Create an account</h2>
      <p className="mt-1 text-sm text-slate-600">
        Your password is used by the client to create an SRP proof.
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
            autoComplete="new-password"
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
          {isSubmitting ? "Creating account…" : "Register"}
        </button>
      </form>

      {error && (
        <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700" role="alert">
          {error}
        </p>
      )}
      {userId && (
        <div className="mt-4 rounded-md bg-emerald-50 p-4 text-sm text-emerald-800" role="status">
          <p>Registration succeeded. Your user ID is:</p>
          <p className="mt-1 break-all font-mono text-xs">{userId}</p>
          <button
            className="mt-3 font-semibold underline"
            onClick={onGoToLogin}
            type="button"
          >
            Continue to login
          </button>
        </div>
      )}
    </section>
  )
}
