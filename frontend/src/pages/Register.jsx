import { useLayoutEffect, useRef, useState } from "react"
import gsap from "gsap"
import {
  getBaseUrl,
  register,
  RegistrationError,
} from "../api/zkauth.js"

export default function Register() {
  const formRef = useRef(null)
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [userId, setUserId] = useState(null)
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
    setUserId(null)
    setIsSubmitting(true)
    try {
      const id = await register(getBaseUrl(), username, password)
      setUserId(id)
      setPassword("")
      setShowPassword(false)
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
    <div className="register-content">
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
              placeholder="Choose a username"
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
              autoComplete="new-password"
              className="auth-input auth-input--password"
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Create a strong password"
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

        <div className="proof-hint">
          <span className="proof-hint-icon" aria-hidden="true">⌁</span>
          <span>Your password is used locally to create an SRP verifier.</span>
        </div>

        <button className="submit-button" disabled={isSubmitting} type="submit">
          <span>{isSubmitting ? "Creating your identity…" : "Create account"}</span>
          <span className="button-arrow" aria-hidden="true">
            {isSubmitting ? "◌" : "↗"}
          </span>
        </button>
      </form>

      {error && (
        <p className="form-message form-message--error" role="alert">
          <span aria-hidden="true">!</span>
          {error}
        </p>
      )}
      {userId && (
        <div className="form-message form-message--success" role="status">
          <div className="success-icon" aria-hidden="true">✓</div>
          <div>
            <strong>Your identity is ready.</strong>
            <p>Account created. Switch to sign in when you’re ready.</p>
            <code>{userId}</code>
          </div>
        </div>
      )}
    </div>
  )
}
