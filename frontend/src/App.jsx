import { useLayoutEffect, useRef, useState } from "react"
import gsap from "gsap"
import ChainStatus from "./components/ChainStatus.jsx"
import Login from "./pages/Login.jsx"
import Register from "./pages/Register.jsx"

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg viewBox="0 0 32 32" fill="none">
        <path
          d="M3 16s4.7-8 13-8 13 8 13 8-4.7 8-13 8S3 16 3 16Z"
          stroke="currentColor"
          strokeWidth="1.7"
        />
        <circle cx="16" cy="16" r="4" stroke="currentColor" strokeWidth="1.7" />
        <circle cx="16" cy="16" r="1.4" fill="currentColor" />
      </svg>
    </span>
  )
}

function Dashboard({ auth, onLogout }) {
  const [tokenVisible, setTokenVisible] = useState(false)
  const tokenPreview = tokenVisible
    ? auth.token
    : `${auth.token.slice(0, 18)}${"•".repeat(24)}`

  return (
    <section className="dashboard-panel glass-panel">
      <div className="dashboard-heading">
        <div className="signed-in-label">
          <span className="status-dot" />
          Authenticated session
        </div>
        <button className="quiet-button" onClick={onLogout} type="button">
          Sign out
          <span aria-hidden="true">↗</span>
        </button>
      </div>

      <div className="welcome-block">
        <p className="eyebrow">Welcome back</p>
        <h2>{auth.claims.username}</h2>
        <p>Your identity has been verified with a signed Argus token.</p>
      </div>

      <div className="claims-card">
        <div className="card-heading">
          <div>
            <span className="card-kicker">01 / IDENTITY</span>
            <h3>Verified claims</h3>
          </div>
          <span className="verified-badge">Verified</span>
        </div>
        <pre>{JSON.stringify(auth.claims, null, 2)}</pre>
      </div>

      <div className="token-card">
        <div className="card-heading">
          <div>
            <span className="card-kicker">02 / SESSION</span>
            <h3>EdDSA token</h3>
          </div>
          <button
            className="text-button"
            onClick={() => setTokenVisible((visible) => !visible)}
            type="button"
          >
            {tokenVisible ? "Hide token" : "Reveal token"}
          </button>
        </div>
        <p className="token-value">{tokenPreview}</p>
      </div>

      <ChainStatus />
      <p className="dashboard-footnote">
        Session data lives in memory and is cleared when you sign out or reload.
      </p>
    </section>
  )
}

export default function App() {
  const [view, setView] = useState("register")
  const [auth, setAuth] = useState(null)
  const sceneRef = useRef(null)
  const spotlightRef = useRef(null)
  const authPanelRef = useRef(null)

  useLayoutEffect(() => {
    const root = sceneRef.current
    if (!root) return undefined

    const media = gsap.matchMedia()
    media.add("(prefers-reduced-motion: no-preference)", () => {
      const context = gsap.context(() => {
        gsap.from(".hero-intro > *", {
          y: 22,
          opacity: 0,
          duration: 0.8,
          stagger: 0.11,
          ease: "power3.out",
        })
        gsap.from(".hero-feature", {
          x: -18,
          opacity: 0,
          duration: 0.55,
          stagger: 0.12,
          delay: 0.42,
          ease: "power2.out",
        })
        gsap.to(".ambient-orb--violet", {
          x: 34,
          y: -26,
          duration: 7,
          repeat: -1,
          yoyo: true,
          ease: "sine.inOut",
        })
        gsap.to(".ambient-orb--cyan", {
          x: -30,
          y: 28,
          duration: 8,
          repeat: -1,
          yoyo: true,
          ease: "sine.inOut",
        })
      }, root)

      return () => context.revert()
    })

    return () => media.revert()
  }, [])

  useLayoutEffect(() => {
    const panel = authPanelRef.current
    if (!panel || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return undefined
    }

    const context = gsap.context(() => {
      gsap.fromTo(
        ".auth-panel-content",
        { y: 16, opacity: 0 },
        { y: 0, opacity: 1, duration: 0.55, ease: "power3.out" },
      )
    }, panel)

    return () => context.revert()
  }, [view])

  function handlePointerMove(event) {
    if (
      !sceneRef.current ||
      !spotlightRef.current ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      return
    }
    const bounds = sceneRef.current.getBoundingClientRect()
    const x = event.clientX - bounds.left
    const y = event.clientY - bounds.top
    gsap.to(spotlightRef.current, {
      x,
      y,
      duration: 0.65,
      ease: "power2.out",
      overwrite: true,
    })
  }

  function handleLoginSuccess(nextAuth) {
    setAuth(nextAuth)
    setView("dashboard")
  }

  function handleLogout() {
    setAuth(null)
    setView("login")
  }

  return (
    <main
      className="app-scene"
      onPointerMove={handlePointerMove}
      ref={sceneRef}
    >
      <div className="scene-grid" aria-hidden="true" />
      <div className="ambient-orb ambient-orb--violet" aria-hidden="true" />
      <div className="ambient-orb ambient-orb--cyan" aria-hidden="true" />
      <div className="pointer-glow" ref={spotlightRef} aria-hidden="true" />

      <div className="app-shell">
        <header className="topbar">
          <div className="brand" aria-label="Argus">
            <BrandMark />
            <span>argus<span className="brand-period">.</span></span>
          </div>
          <div className="topbar-note">
            <span className="live-indicator" />
            <span>AUTH, WITH PROOF</span>
          </div>
        </header>

        <div className="main-layout">
          <section className="hero-intro">
            <div className="hero-eyebrow">
              <span className="eyebrow-line" />
              PRIVATE BY DESIGN
            </div>
            <h1>
              Your password
              <br />
              stays <span>yours.</span>
            </h1>
            <p className="hero-description">
              Sign in with a cryptographic proof, not a password sent over the
              wire. A calmer, more considered foundation for identity.
            </p>

            <div className="feature-list">
              <div className="hero-feature">
                <span className="feature-index">01</span>
                <span className="feature-symbol">⌁</span>
                <span>
                  <strong>SRP-6a password proof</strong>
                  <small>Your password never leaves your device.</small>
                </span>
              </div>
              <div className="hero-feature">
                <span className="feature-index">02</span>
                <span className="feature-symbol">◈</span>
                <span>
                  <strong>Ed25519-signed sessions</strong>
                  <small>Tokens can be verified locally.</small>
                </span>
              </div>
              <div className="hero-feature">
                <span className="feature-index">03</span>
                <span className="feature-symbol">⟲</span>
                <span>
                  <strong>Verifiable event history</strong>
                  <small>Authentication events link by hash.</small>
                </span>
              </div>
            </div>

            <div className="hero-caption">
              <span className="caption-line" />
              <span>IDENTITY SHOULD BE PROVABLE, NOT EXPOSED.</span>
            </div>
          </section>

          <section className="auth-column">
            <div className="auth-panel glass-panel" ref={authPanelRef}>
              {view !== "dashboard" ? (
                <>
                  <div className="auth-panel-heading">
                    <div>
                      <p className="eyebrow">YOUR SECURE SPACE</p>
                      <h2>{view === "register" ? "Create your account" : "Welcome back"}</h2>
                      <p>
                        {view === "register"
                          ? "Start with your identity. Your password stays with you."
                          : "Prove it’s you. Your password stays on your device."}
                      </p>
                    </div>
                    <div className="auth-emblem" aria-hidden="true">
                      <BrandMark />
                    </div>
                  </div>

                  <div className="auth-tabs" role="tablist" aria-label="Account access">
                    <button
                      aria-selected={view === "login"}
                      className={view === "login" ? "auth-tab is-active" : "auth-tab"}
                      onClick={() => setView("login")}
                      role="tab"
                      type="button"
                    >
                      Sign in
                    </button>
                    <button
                      aria-selected={view === "register"}
                      className={view === "register" ? "auth-tab is-active" : "auth-tab"}
                      onClick={() => setView("register")}
                      role="tab"
                      type="button"
                    >
                      Create account
                    </button>
                  </div>

                  <div className="auth-panel-content">
                    {view === "register" && (
                      <Register onGoToLogin={() => setView("login")} />
                    )}
                    {view === "login" && (
                      <Login onLoginSuccess={handleLoginSuccess} />
                    )}
                  </div>

                  <div className="form-security-note">
                    <span aria-hidden="true">✳</span>
                    <span>Protected by a zero-knowledge password proof</span>
                  </div>
                </>
              ) : (
                <div className="auth-panel-content">
                  <Dashboard auth={auth} onLogout={handleLogout} />
                </div>
              )}
            </div>
            <p className="auth-caption">
              By continuing, you’re proving your identity without revealing your
              password.
            </p>
          </section>
        </div>

        <footer className="site-footer">
          <span>ARGUS AUTHENTICATION</span>
          <span>BUILT ON PROTOCOLS, NOT PROMISES</span>
        </footer>
      </div>
    </main>
  )
}
