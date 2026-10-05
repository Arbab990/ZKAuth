import { useLayoutEffect, useRef, useState } from "react"
import gsap from "gsap"
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
  const formRef = useRef(null)
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)

  useLayoutEffect(() => {
    const form = formRef.current
    if (!form || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return undefined
    }

    const context = gsap.context(() => {
      gsap.from(".form-field, .submit-button", {
        y: 12,
        opacity: 0,
        duration: 0.42,
        stagger: 0.08,
        ease: "power2.out",
      })
    }, form)

    return () => context.revert()
  }, [])

  async function handleSubmit(event) {
    event.preventDefault()
    setError("")
    setIsSubmitting(true)
    try {
      const result = await login(getBaseUrl(), username, password)
      const publicKey = await fetchPublicKey(getBaseUrl())
      const claims = await verifyToken(result.token, publicKey)
      onLoginSuccess({ token: result.token, claims })
    } catch (caught) {
      setError(messageForError(caught))
    } finally {
      setIsSubmitting(false)
      setPassword("")
      setShowPassword(false)
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit} ref={formRef}>
      <label className="form-field">
        <span className="field-label">Username</span>
        <span className="input-wrap">
          <span className="input-icon" aria-hidden="true">@</span>
          <input
            autoComplete="username"
            autoCapitalize="none"
            className="auth-input"
            onChange={(event) => setUsername(event.target.value)}
            placeholder="Your username"
            required
            type="text"
            value={username}
          />
        </span>
      </label>

      <label className="form-field">
        <span className="field-label">Password</span>
        <span className="input-wrap">
          <span className="input-icon" aria-hidden="true">◇</span>
          <input
            autoComplete="current-password"
            className="auth-input auth-input--password"
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Your password"
            required
            type={showPassword ? "text" : "password"}
            value={password}
          />
          <button
            aria-label={showPassword ? "Hide password" : "Show password"}
            aria-pressed={showPassword}
            className="password-toggle"
            onClick={() => setShowPassword((visible) => !visible)}
            type="button"
          >
            {showPassword ? "Hide" : "Show"}
          </button>
        </span>
      </label>

      <button className="submit-button" disabled={isSubmitting} type="submit">
        <span>{isSubmitting ? "Verifying proof…" : "Sign in securely"}</span>
        <span className="button-arrow" aria-hidden="true">
          {isSubmitting ? "◌" : "↗"}
        </span>
      </button>

      {error && (
        <p className="form-message form-message--error" role="alert">
          <span aria-hidden="true">!</span>
          {error}
        </p>
      )}
    </form>
  )
}
