import { useState } from "react"
import ChainStatus from "./components/ChainStatus.jsx"
import Login from "./pages/Login.jsx"
import Register from "./pages/Register.jsx"

function Dashboard({ auth, onLogout }) {
  return (
    <section className="mx-auto w-full max-w-2xl rounded-xl bg-white p-6 shadow">
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium uppercase tracking-wide text-emerald-700">
            Signed in
          </p>
          <h2 className="mt-1 text-2xl font-semibold text-slate-900">
            Welcome, {auth.claims.username}
          </h2>
        </div>
        <button
          className="rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
          onClick={onLogout}
          type="button"
        >
          Log out
        </button>
      </div>

      <div className="space-y-5">
        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-700">Token claims</h3>
          <pre className="overflow-x-auto rounded-md bg-slate-900 p-4 text-xs text-emerald-200">
            {JSON.stringify(auth.claims, null, 2)}
          </pre>
        </div>

        <div>
          <h3 className="mb-2 text-sm font-semibold text-slate-700">Session token</h3>
          <p className="break-all rounded-md bg-slate-100 p-3 font-mono text-xs text-slate-700">
            {auth.token}
          </p>
        </div>

        <ChainStatus />
      </div>
    </section>
  )
}

export default function App() {
  const [view, setView] = useState("register")
  const [auth, setAuth] = useState(null)

  function handleLoginSuccess(nextAuth) {
    setAuth(nextAuth)
    setView("dashboard")
  }

  function handleLogout() {
    setAuth(null)
    setView("login")
  }

  return (
    <main className="min-h-screen bg-slate-100 px-4 py-10 text-slate-900">
      <div className="mx-auto max-w-2xl">
        <header className="mb-8 text-center">
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-indigo-700">
            ZKAuth demo
          </p>
          <h1 className="mt-2 text-3xl font-bold">Authentication built on real crypto</h1>
          <p className="mt-2 text-slate-600">
            Register and log in with SRP, then verify an Ed25519-signed token.
          </p>
        </header>

        {view !== "dashboard" && (
          <nav className="mb-5 flex justify-center gap-2" aria-label="Authentication pages">
            <button
              className={
                view === "register"
                  ? "rounded-md bg-indigo-700 px-4 py-2 text-sm font-medium text-white"
                  : "rounded-md bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
              }
              onClick={() => setView("register")}
              type="button"
            >
              Register
            </button>
            <button
              className={
                view === "login"
                  ? "rounded-md bg-indigo-700 px-4 py-2 text-sm font-medium text-white"
                  : "rounded-md bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
              }
              onClick={() => setView("login")}
              type="button"
            >
              Login
            </button>
          </nav>
        )}

        {view === "register" && <Register onGoToLogin={() => setView("login")} />}
        {view === "login" && <Login onLoginSuccess={handleLoginSuccess} />}
        {view === "dashboard" && auth && (
          <Dashboard auth={auth} onLogout={handleLogout} />
        )}
      </div>
    </main>
  )
}
