"use client"

import { useState, useRef, useCallback } from "react"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

/* ═══════════════════════════════════════════════════════════ TYPES ══ */

const AGENT_ORDER = [
  "normalizer",
  "surface_enum",
  "exfil_analyst",
  "nist_mapper",
  "csv_builder",
] as const

type AgentId = typeof AGENT_ORDER[number]

const AGENT_META: Record<AgentId, { label: string; icon: string }> = {
  normalizer:    { label: "Normalizer",           icon: "⬡" },
  surface_enum:  { label: "Surface Enumerator",   icon: "⬡" },
  exfil_analyst: { label: "Exfiltration Analyst", icon: "⬡" },
  nist_mapper:   { label: "NIST Mapper",          icon: "⬡" },
  csv_builder:   { label: "CSV Builder",          icon: "⬡" },
}

type AgentStatus = "idle" | "running" | "done" | "error"

interface AgentState {
  status: AgentStatus
  desc?: string
  stats?: Record<string, unknown>
  error?: string
}

interface CompletePayload {
  total_vectors: number
  familles_nist: string[]
  resume_nist: string
  warnings: string[]
  csv_rows: Array<Record<string, string>>
  nist_mapping: Record<string, unknown>
}

/* ═══════════════════════════════════════════════════════════ PAGE ═══ */

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

export default function Page() {
  const [input, setInput]       = useState("")
  const [loading, setLoading]   = useState(false)
  const [started, setStarted]   = useState(false)
  const [agents, setAgents]     = useState<Record<AgentId, AgentState>>(
    () => Object.fromEntries(AGENT_ORDER.map((id) => [id, { status: "idle" }])) as Record<AgentId, AgentState>
  )
  const [result, setResult]     = useState<CompletePayload | null>(null)
  const [error, setError]       = useState<string | null>(null)
  const esRef = useRef<EventSource | null>(null)

  const resetState = useCallback(() => {
    setAgents(Object.fromEntries(AGENT_ORDER.map((id) => [id, { status: "idle" }])) as Record<AgentId, AgentState>)
    setResult(null)
    setError(null)
    setStarted(false)
  }, [])

  const handleSubmit = useCallback(() => {
    if (!input.trim() || loading) return

    if (esRef.current) { esRef.current.close(); esRef.current = null }
    resetState()
    setLoading(true)
    setStarted(true)

    const url = `${API_BASE}/analyze/stream?objet_it=${encodeURIComponent(input.trim())}`
    const es = new EventSource(url)
    esRef.current = es

    const patchAgent = (id: AgentId, patch: Partial<AgentState>) =>
      setAgents((prev) => ({ ...prev, [id]: { ...prev[id], ...patch } }))

    es.addEventListener("agent_start", (e) => {
      const d = JSON.parse(e.data)
      patchAgent(d.agent as AgentId, { status: "running", desc: d.desc })
    })

    es.addEventListener("agent_done", (e) => {
      const d = JSON.parse(e.data)
      patchAgent(d.agent as AgentId, { status: "done", stats: d.stats })
    })

    es.addEventListener("agent_error", (e) => {
      const d = JSON.parse(e.data)
      patchAgent(d.agent as AgentId, { status: "error", error: d.error })
    })

    es.addEventListener("complete", (e) => {
      const d: CompletePayload = JSON.parse(e.data)
      setResult(d)
      setLoading(false)
      es.close()
    })

    es.onerror = () => {
      setError("Connection to backend lost. Is the API server running?")
      setLoading(false)
      es.close()
    }
  }, [input, loading, resetState])

  const handleDownloadCSV = () => {
    if (!result?.csv_rows?.length) return
    const headers = ["env", "detail_de_surface", "technique_exploitee", "explication_technique"]
    const rows = [
      headers.join(","),
      ...result.csv_rows.map((r) =>
        headers.map((h) => `"${(r[h] ?? "").replace(/"/g, '""')}"`).join(",")
      ),
    ].join("\n")
    const blob = new Blob(["\uFEFF" + rows], { type: "text/csv;charset=utf-8;" })
    const a = document.createElement("a")
    a.href = URL.createObjectURL(blob)
    a.download = `registre_${input.toLowerCase().replace(/\s+/g, "_")}.csv`
    a.click()
  }

  /* ─── render ─────────────────────────────────────────────────────── */
  return (
    <div className="relative min-h-screen bg-[#0d0d0f] text-[#e2e8f0] font-mono overflow-hidden">

      {/* Scanline overlay */}
      <div className="pointer-events-none fixed inset-0 z-50"
        style={{ background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px)" }} />

      {/* Grid */}
      <div className="pointer-events-none absolute inset-0 opacity-[0.03]">
        <div className="h-full w-full" style={{
          backgroundImage: "linear-gradient(currentColor 1px,transparent 1px),linear-gradient(90deg,currentColor 1px,transparent 1px)",
          backgroundSize: "32px 32px",
        }} />
      </div>

      {/* Glow orb */}
      <div className="pointer-events-none absolute top-[-200px] left-1/2 -translate-x-1/2 w-[700px] h-[400px] rounded-full opacity-10"
        style={{ background: "radial-gradient(ellipse,#00ff9d 0%,transparent 70%)" }} />

      <div className="relative mx-auto max-w-4xl px-6 py-16 space-y-10">

        {/* ── HEADER ── */}
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="text-[#00ff9d] text-xs tracking-[0.3em] uppercase">Swarm Multi-Agents</span>
            <span className="h-px flex-1 bg-[#00ff9d]/20" />
            <span className="text-[10px] text-[#4a5568] tabular-nums">v2.0</span>
          </div>
          <h1 className="text-3xl font-light tracking-tight text-white">
            Registre de Vecteurs<br />
            <span className="text-[#00ff9d]">d'Exfiltration</span>
          </h1>
          <p className="text-xs text-[#4a5568] mt-2">
            START → Normalizer → Surface_Enumerator → Exfiltration_Analyst → NIST_Mapper → CSV_Builder → END
          </p>
        </div>

        {/* ── FORM ── */}
        <div className="space-y-4 max-w-xl">
          <div>
            <label className="text-[10px] uppercase tracking-[0.25em] text-[#4a5568] block mb-2">
              Objet IT à analyser
            </label>
            <div className="flex gap-3">
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
                placeholder="ex: laptop, smartphone BYOD, clé USB…"
                disabled={loading}
                className="flex-1 h-10 bg-[#111115] border border-[#1e2030] text-sm px-3 rounded
                  text-[#e2e8f0] placeholder:text-[#2d3748] outline-none
                  focus:border-[#00ff9d]/50 focus:ring-1 focus:ring-[#00ff9d]/20
                  disabled:opacity-40 transition-colors"
              />
              <button
                onClick={handleSubmit}
                disabled={loading || !input.trim()}
                className="h-10 px-5 text-xs tracking-widest uppercase font-medium
                  border border-[#00ff9d]/60 text-[#00ff9d] rounded
                  hover:bg-[#00ff9d]/10 disabled:opacity-30 disabled:cursor-not-allowed
                  transition-all active:scale-95"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="inline-block w-3 h-3 border border-[#00ff9d] border-t-transparent rounded-full animate-spin" />
                    Running
                  </span>
                ) : "Execute"}
              </button>
            </div>
            <p className="text-[10px] text-[#2d3748] mt-1.5">
              Exemples : laptop, Smartphone BYOD, Serveur NAS, Imprimante réseau, smartwatch
            </p>
          </div>
        </div>

        {/* ── PIPELINE ── */}
        {started && (
          <div className="space-y-2">
            <div className="text-[10px] uppercase tracking-[0.25em] text-[#4a5568] mb-3">
              Pipeline d'agents
            </div>

            {AGENT_ORDER.map((id, i) => {
              const ag = agents[id]
              const meta = AGENT_META[id]
              return (
                <div key={id}
                  className={`flex items-start gap-4 p-3 rounded border transition-all duration-300
                    ${ag.status === "running" ? "border-[#00ff9d]/40 bg-[#00ff9d]/5" :
                      ag.status === "done"    ? "border-[#1e2030] bg-[#111115]" :
                      ag.status === "error"   ? "border-red-500/40 bg-red-500/5" :
                                               "border-[#1a1a24] bg-transparent opacity-40"}`}
                >
                  {/* Status dot */}
                  <div className="mt-0.5 flex-shrink-0 w-4 h-4 flex items-center justify-center">
                    {ag.status === "idle"    && <span className="w-2 h-2 rounded-full bg-[#2d3748]" />}
                    {ag.status === "running" && <span className="w-2 h-2 rounded-full bg-[#00ff9d] animate-pulse" />}
                    {ag.status === "done"    && <span className="text-[#00ff9d] text-xs">✓</span>}
                    {ag.status === "error"   && <span className="text-red-400 text-xs">✕</span>}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-medium ${
                        ag.status === "done" ? "text-[#e2e8f0]" :
                        ag.status === "running" ? "text-[#00ff9d]" :
                        ag.status === "error" ? "text-red-400" : "text-[#4a5568]"
                      }`}>{meta.label}</span>
                      <span className="text-[10px] text-[#2d3748]">#{i + 1}</span>
                    </div>

                    {ag.desc && ag.status === "running" && (
                      <p className="text-[10px] text-[#4a5568] mt-0.5">{ag.desc}</p>
                    )}

                    {ag.stats && ag.status === "done" && (
                      <div className="flex flex-wrap gap-2 mt-1">
                        {Object.entries(ag.stats).map(([k, v]) => (
                          <span key={k} className="text-[10px] bg-[#1a1a24] border border-[#1e2030] px-1.5 py-0.5 rounded">
                            <span className="text-[#4a5568]">{k}: </span>
                            <span className="text-[#00ff9d]">
                              {Array.isArray(v) ? v.join(", ") || "—" : String(v)}
                            </span>
                          </span>
                        ))}
                      </div>
                    )}

                    {ag.error && (
                      <p className="text-[10px] text-red-400 mt-0.5">{ag.error}</p>
                    )}
                  </div>

                  {ag.status === "running" && (
                    <div className="flex-shrink-0 flex gap-0.5 mt-1">
                      {[0,1,2].map(j => (
                        <span key={j} className="inline-block w-1 h-3 bg-[#00ff9d]/60 rounded-sm animate-pulse"
                          style={{ animationDelay: `${j * 150}ms` }} />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}

        {/* ── ERROR ── */}
        {error && (
          <div className="border border-red-500/30 bg-red-500/5 rounded p-4 text-xs text-red-400">
            {error}
          </div>
        )}

        {/* ── RESULT ── */}
        {result && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <span className="text-[10px] uppercase tracking-[0.25em] text-[#4a5568]">Résultat</span>
              <span className="h-px flex-1 bg-[#1e2030]" />
              <span className="text-[10px] text-[#00ff9d]">✓ Analyse terminée</span>
            </div>

            {/* Stats bar */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "Vecteurs identifiés", value: result.total_vectors },
                { label: "Familles NIST", value: result.familles_nist?.join(", ") || "—" },
                { label: "Avertissements", value: result.warnings?.length ?? 0 },
              ].map(({ label, value }) => (
                <div key={label} className="border border-[#1e2030] bg-[#111115] rounded p-3">
                  <div className="text-[10px] text-[#4a5568] uppercase tracking-wider mb-1">{label}</div>
                  <div className="text-sm text-[#00ff9d] font-medium truncate">{String(value)}</div>
                </div>
              ))}
            </div>

            {/* NIST summary */}
            {result.resume_nist && (
              <div className="border border-[#1e2030] bg-[#111115] rounded p-4">
                <div className="text-[10px] uppercase tracking-wider text-[#4a5568] mb-2">Résumé NIST 800-53</div>
                <p className="text-xs text-[#94a3b8] leading-relaxed">{result.resume_nist}</p>
              </div>
            )}

            {/* Preview table */}
            {result.csv_rows?.length > 0 && (
              <div className="border border-[#1e2030] rounded overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 bg-[#111115] border-b border-[#1e2030]">
                  <span className="text-[10px] uppercase tracking-wider text-[#4a5568]">
                    Aperçu — {result.csv_rows.length} vecteurs
                  </span>
                  <button
                    onClick={handleDownloadCSV}
                    className="text-[10px] text-[#00ff9d] border border-[#00ff9d]/30 px-2 py-1 rounded
                      hover:bg-[#00ff9d]/10 transition-colors uppercase tracking-wider"
                  >
                    ↓ CSV
                  </button>
                </div>
                <div className="overflow-x-auto max-h-80 overflow-y-auto">
                  <table className="w-full text-[10px]">
                    <thead className="sticky top-0 bg-[#0d0d0f]">
                      <tr>
                        {["Env", "Surface", "Technique", "Explication"].map((h) => (
                          <th key={h} className="text-left px-3 py-2 text-[#4a5568] border-b border-[#1e2030] font-normal uppercase tracking-wider whitespace-nowrap">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {result.csv_rows.slice(0, 20).map((row, i) => (
                        <tr key={i} className={i % 2 === 0 ? "bg-[#0d0d0f]" : "bg-[#111115]"}>
                          <td className="px-3 py-2 text-[#4a5568] whitespace-nowrap max-w-[120px] truncate">{row.env}</td>
                          <td className="px-3 py-2 text-[#94a3b8] max-w-[180px] truncate">{row.detail_de_surface}</td>
                          <td className="px-3 py-2 text-[#00ff9d] max-w-[160px] truncate">{row.technique_exploitee}</td>
                          <td className="px-3 py-2 text-[#64748b] max-w-[260px] truncate">{row.explication_technique}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {result.csv_rows.length > 20 && (
                    <div className="text-center py-2 text-[10px] text-[#2d3748]">
                      + {result.csv_rows.length - 20} autres vecteurs dans le CSV
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
