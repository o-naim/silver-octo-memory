"use client"

import { useState } from "react"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

/* ================= TYPES ================= */

type WebhookResponse = Record<string, unknown>

/* ================= PAGE ================= */

export default function Page() {
  const [apiKey, setApiKey] = useState("")
  const [loading, setLoading] = useState(false)
  const [response, setResponse] = useState<WebhookResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async () => {
    if (!apiKey) return

    setLoading(true)
    setError(null)
    setResponse(null)

    try {
      const res = await fetch("https://your-webhook-url.com", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ apiKey }),
      })

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }

      const data: WebhookResponse = await res.json()
      setResponse(data)
    } catch (err) {
      console.error(err)
      setError("Execution failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative min-h-screen bg-terminal text-terminal-foreground font-mono">
      
      {/* GRID */}
      <div className="pointer-events-none absolute inset-0 opacity-[0.035]">
        <div
          className="h-full w-full"
          style={{
            backgroundImage:
              "linear-gradient(currentColor 1px, transparent 1px), linear-gradient(90deg, currentColor 1px, transparent 1px)",
            backgroundSize: "28px 28px",
          }}
        />
      </div>

      <div className="relative mx-auto max-w-5xl px-6 py-20 space-y-12">
        
        {/* HEADER */}
        <div className="border-b border-terminal-border pb-4">
          <h1 className="text-2xl tracking-tight">
            Langchain Swarm to Excel Demo
          </h1>
          <p className="text-xs text-terminal-muted mt-1">
            Custom LangChain Model Trigger
          </p>
        </div>

        {/* FORM */}
        <div className="max-w-md space-y-6">
          <Field>
            <FieldLabel className="text-xs uppercase tracking-wide text-terminal-muted">
              Vector Exfiltration 
            </FieldLabel>

            <Input
              type=""
              placeholder="sentence or word"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="mt-2 h-10 bg-transparent border-terminal-border focus:border-terminal-accent focus:ring-0"
            />

            <FieldDescription className="text-[11px] text-terminal-muted">
              Exfiltration / Threat Vector to be studied
            </FieldDescription>
          </Field>

          <Button
            onClick={handleSubmit}
            disabled={loading}
            className="h-10 border border-terminal-accent bg-transparent hover:bg-terminal-header text-terminal-accent"
          >
            {loading ? "Executing..." : "Execute"}
          </Button>
        </div>

        {/* OUTPUT */}
        {(response || error) && (
          <div className="border border-terminal-border bg-terminal-widget p-4 rounded-md">
            
            <div className="mb-3 flex items-center justify-between text-xs text-terminal-muted">
              <span>Execution Result</span>
              {error ? (
                <span className="text-terminal-danger">error</span>
              ) : (
                <span className="text-terminal-success">success</span>
              )}
            </div>

            {error && (
              <div className="text-xs text-terminal-danger">
                {error}
              </div>
            )}

            {response && (
              <pre className="text-xs leading-relaxed overflow-x-auto text-terminal-foreground">
                {JSON.stringify(response, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  )
}