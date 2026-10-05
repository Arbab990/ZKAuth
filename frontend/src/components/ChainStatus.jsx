import { useEffect, useState } from "react"
import axios from "axios"
import { getBaseUrl } from "../api/zkauth.js"

export default function ChainStatus() {
  const [status, setStatus] = useState({ kind: "loading" })

  useEffect(() => {
    let isMounted = true
    axios
      .get(getBaseUrl().replace(/\/$/, "") + "/api/admin/verify-chain")
      .then(({ data }) => {
        if (!isMounted) return
        if (data?.valid === true) {
          setStatus({ kind: "valid", eventCount: data.event_count })
        } else if (data?.valid === false) {
          setStatus({ kind: "broken", eventId: data.broken_at_event_id })
        } else {
          setStatus({ kind: "error" })
        }
      })
      .catch(() => {
        if (isMounted) setStatus({ kind: "error" })
      })

    return () => {
      isMounted = false
    }
  }, [])

  if (status.kind === "loading") {
    return (
      <section className="rounded-lg border border-slate-200 p-4" aria-live="polite">
        <h3 className="font-semibold text-slate-800">Audit-chain integrity</h3>
        <p className="mt-1 text-sm text-slate-600">Checking the event chain…</p>
      </section>
    )
  }

  if (status.kind === "valid") {
    return (
      <section className="rounded-lg border border-emerald-200 bg-emerald-50 p-4" aria-live="polite">
        <h3 className="font-semibold text-emerald-800">Audit chain healthy</h3>
        <p className="mt-1 text-sm text-emerald-700">
          Valid hash chain · {status.eventCount} events
        </p>
      </section>
    )
  }

  if (status.kind === "broken") {
    return (
      <section className="rounded-lg border border-red-200 bg-red-50 p-4" aria-live="polite">
        <h3 className="font-semibold text-red-800">Audit chain is broken</h3>
        <p className="mt-1 text-sm text-red-700">
          First invalid event: {status.eventId}
        </p>
      </section>
    )
  }

  return (
    <section className="rounded-lg border border-amber-200 bg-amber-50 p-4" role="status">
      <h3 className="font-semibold text-amber-800">Audit-chain status unavailable</h3>
      <p className="mt-1 text-sm text-amber-700">
        Could not check chain integrity. Ensure the backend is running.
      </p>
    </section>
  )
}
