import { useEffect, useState } from "react"
import axios from "axios"
import { getBaseUrl } from "../api/zkauth.js"

export default function ChainStatus() {
  const [status, setStatus] = useState({ kind: "loading" })
  const [refreshCount, setRefreshCount] = useState(0)

  useEffect(() => {
    let isMounted = true
    setStatus({ kind: "loading" })
    axios
      .get(getBaseUrl().replace(/\/$/, "") + "/api/admin/verify-chain")
      .then(({ data }) => {
        if (!isMounted) return
        if (data?.valid === true && Number.isInteger(data.event_count)) {
          setStatus({ kind: "valid", eventCount: data.event_count })
        } else if (
          data?.valid === false &&
          Number.isInteger(data.broken_at_event_id)
        ) {
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
  }, [refreshCount])

  const isLoading = status.kind === "loading"

  return (
    <section
      className={`chain-status chain-status--${status.kind}`}
      aria-live="polite"
    >
      <div className="chain-status-mark" aria-hidden="true">
        {status.kind === "valid" ? "✓" : status.kind === "broken" ? "!" : "↻"}
      </div>
      <div className="chain-status-copy">
        <span className="card-kicker">03 / AUDIT TRAIL</span>
        <h3>
          {status.kind === "loading" && "Checking event chain"}
          {status.kind === "valid" && "Audit chain healthy"}
          {status.kind === "broken" && "Chain integrity issue"}
          {status.kind === "error" && "Chain status unavailable"}
        </h3>
        <p>
          {status.kind === "loading" && "Verifying linked event hashes…"}
          {status.kind === "valid" && `${status.eventCount} events verified`}
          {status.kind === "broken" &&
            `First invalid event: ${status.eventId}`}
          {status.kind === "error" &&
            "The diagnostic may be disabled or the service is unreachable."}
        </p>
      </div>
      <button
        aria-label="Refresh audit-chain status"
        className={isLoading ? "refresh-button is-spinning" : "refresh-button"}
        disabled={isLoading}
        onClick={() => setRefreshCount((count) => count + 1)}
        type="button"
      >
        ↻
      </button>
    </section>
  )
}
