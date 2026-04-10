"""
Swarm Exfiltration API — FastAPI backend
Runs the LangGraph swarm and streams agent progress via SSE.
"""

import os
import json
import csv
import io
import asyncio
from datetime import datetime
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

# ── LangGraph / LangChain ─────────────────────────────────────────────────────
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from typing import TypedDict, List
from pinecone import Pinecone
import requests as http_requests

# ── Config ────────────────────────────────────────────────────────────────────
GROQ_API_KEY     = os.getenv("GROQ_API_KEY")
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
HF_API_KEY       = os.getenv("HF_API_KEY")
PINECONE_INDEX   = os.getenv("PINECONE_INDEX",    "threat-vectors")
HF_MODEL         = "BAAI/bge-large-en-v1.5"
HF_API_URL       = f"https://router.huggingface.co/hf-inference/models/{HF_MODEL}/pipeline/feature-extraction"

# ── LLM & Pinecone clients ────────────────────────────────────────────────────
llm      = ChatGroq(model="llama-3.3-70b-versatile", api_key=GROQ_API_KEY, temperature=0.2)
llm_json = llm.bind(response_format={"type": "json_object"})
pc       = Pinecone(api_key=PINECONE_API_KEY)
index    = pc.Index(PINECONE_INDEX)

# ── State ─────────────────────────────────────────────────────────────────────
class ExfilState(TypedDict):
    raw_submission: str
    normalized: dict
    surfaces: list
    exfil_vectors: list
    nist_mapping: dict
    csv_rows: list
    enrichment_context: str
    orchestration_warnings: list

# ── Embedding ─────────────────────────────────────────────────────────────────
def embed(query: str) -> list:
    prefixed = f"Represent this sentence for searching relevant passages: {query}"
    r = http_requests.post(
        HF_API_URL,
        headers={"Authorization": f"Bearer {HF_API_KEY}"},
        json={"inputs": prefixed},
        timeout=30,
    )
    r.raise_for_status()
    vector = r.json()
    return vector[0] if isinstance(vector[0], list) else vector

# ── Agent prompts ─────────────────────────────────────────────────────────────
NORMALIZER_SYSTEM = """Tu es un agent de normalisation specialise en cybersecurite.
On te donne un objet IT brut. Produis un JSON structure avec :
- asset, asset_type, environments, interfaces, os_platforms, connectivity, data_zones
Retourne UNIQUEMENT du JSON valide, pas de markdown."""

SURFACE_SYSTEM = """Tu es un agent d'enumeration de surfaces d'exfiltration.
Produis une liste JSON exhaustive de surfaces exploitables.
Chaque surface: env, surface_id, nom, definition, categorie, interfaces_liees.
Minimum 20 surfaces pour un laptop. Retourne JSON avec cle "surfaces".
UNIQUEMENT du JSON valide.
Contexte RAG : {rag_context}"""

EXFIL_SYSTEM = """Tu es un analyste expert en exfiltration de donnees.
Pour CHAQUE surface, identifie toutes les techniques d'exfiltration.
Chaque entree: env, detail_de_surface, technique_exploitee, explication_technique.
Minimum 30 techniques pour un laptop. Retourne JSON avec cle "vectors".
UNIQUEMENT du JSON valide.
Contexte ATT&CK / CVE : {rag_context}"""

NIST_EXFIL_SYSTEM = """Tu es un agent de mapping NIST 800-53.
Produis un JSON avec: controls_par_vecteur, familles_prioritaires, resume_couverture.
UNIQUEMENT du JSON valide."""

# ── Agents ────────────────────────────────────────────────────────────────────
def normalizer_agent(state: ExfilState) -> dict:
    r = llm_json.invoke([
        ("system", NORMALIZER_SYSTEM),
        ("human",  f"Objet IT: {state['raw_submission']}"),
    ])
    try:
        normalized = json.loads(r.content)
    except Exception:
        normalized = {"error": "parse_failed", "raw": r.content}
    return {"normalized": normalized}

def surface_enumerator_agent(state: ExfilState) -> dict:
    norm = state["normalized"]
    warnings = list(state.get("orchestration_warnings", []))
    rag_context = "Aucun resultat RAG disponible."
    try:
        q = f"data exfiltration {norm.get('asset','')} {norm.get('asset_type','')} {' '.join(norm.get('interfaces',[])[:5])}"
        vec = embed(q)
        res = index.query(vector=vec, namespace="__default__", top_k=15, include_metadata=True,
                          filter={"$or": [{"source_type": {"$eq": "technique"}}, {"source_type": {"$eq": "vulnerability"}}]})
        if res.get("matches"):
            rag_context = json.dumps([m.get("metadata", {}) for m in res["matches"]], indent=2)
    except Exception as e:
        warnings.append(f"Pinecone: {e}")

    prompt = SURFACE_SYSTEM.replace("{rag_context}", rag_context)
    r = llm_json.invoke([("system", prompt), ("human", f"Objet IT normalise:\n{json.dumps(norm, ensure_ascii=False)}")])
    try:
        data = json.loads(r.content)
        surfaces = data.get("surfaces", data if isinstance(data, list) else [])
    except Exception as e:
        surfaces = []; warnings.append(f"Surface parse: {e}")
    return {"surfaces": surfaces, "enrichment_context": rag_context, "orchestration_warnings": warnings}

def exfil_analyst_agent(state: ExfilState) -> dict:
    warnings = list(state.get("orchestration_warnings", []))
    prompt = EXFIL_SYSTEM.replace("{rag_context}", state.get("enrichment_context", "Aucun"))
    r = llm_json.invoke([("system", prompt), ("human", f"Surfaces:\n{json.dumps(state.get('surfaces',[]), ensure_ascii=False)}")])
    try:
        data = json.loads(r.content)
        vectors = data.get("vectors", data if isinstance(data, list) else [])
    except Exception as e:
        vectors = []; warnings.append(f"Exfil parse: {e}")
    return {"exfil_vectors": vectors, "orchestration_warnings": warnings}

def nist_mapper_agent(state: ExfilState) -> dict:
    techniques = list(set(v.get("technique_exploitee", "") for v in state.get("exfil_vectors", []) if v.get("technique_exploitee")))
    r = llm_json.invoke([("system", NIST_EXFIL_SYSTEM), ("human", f"Techniques:\n{json.dumps(techniques, ensure_ascii=False)}")])
    try:
        nist = json.loads(r.content)
    except Exception:
        nist = {"error": "parse_failed", "familles_prioritaires": [], "resume_couverture": "Indisponible"}
    return {"nist_mapping": nist}

def csv_builder_agent(state: ExfilState) -> dict:
    rows = []
    for v in state.get("exfil_vectors", []):
        row = {
            "env": v.get("env", "Non specifie"),
            "detail_de_surface": v.get("detail_de_surface", ""),
            "technique_exploitee": v.get("technique_exploitee", ""),
            "explication_technique": v.get("explication_technique", ""),
        }
        if row["technique_exploitee"] and row["explication_technique"]:
            rows.append(row)
    return {"csv_rows": rows}

# ── Graph ─────────────────────────────────────────────────────────────────────
def build_swarm():
    b = StateGraph(ExfilState)
    b.add_node("normalizer",    normalizer_agent)
    b.add_node("surface_enum",  surface_enumerator_agent)
    b.add_node("exfil_analyst", exfil_analyst_agent)
    b.add_node("nist_mapper",   nist_mapper_agent)
    b.add_node("csv_builder",   csv_builder_agent)
    b.add_edge(START,            "normalizer")
    b.add_edge("normalizer",     "surface_enum")
    b.add_edge("surface_enum",   "exfil_analyst")
    b.add_edge("exfil_analyst",  "nist_mapper")
    b.add_edge("nist_mapper",    "csv_builder")
    b.add_edge("csv_builder",    END)
    return b.compile()

swarm = build_swarm()

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(title="Swarm Exfiltration API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

AGENT_LABELS = {
    "normalizer":    {"label": "Normalizer",          "desc": "Normalisation de l'objet IT"},
    "surface_enum":  {"label": "Surface Enumerator",  "desc": "Enumération des surfaces + RAG Pinecone"},
    "exfil_analyst": {"label": "Exfiltration Analyst","desc": "Analyse des vecteurs d'exfiltration"},
    "nist_mapper":   {"label": "NIST Mapper",         "desc": "Mapping NIST 800-53"},
    "csv_builder":   {"label": "CSV Builder",         "desc": "Construction du registre"},
}

def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

async def run_swarm_stream(objet_it: str) -> AsyncGenerator[str, None]:
    yield sse("start", {"message": f"Analyse de : {objet_it}", "total_agents": 5})

    state: ExfilState = {
        "raw_submission": objet_it,
        "normalized": {},
        "surfaces": [],
        "exfil_vectors": [],
        "nist_mapping": {},
        "csv_rows": [],
        "enrichment_context": "",
        "orchestration_warnings": [],
    }

    agent_fns = [
        ("normalizer",    normalizer_agent),
        ("surface_enum",  surface_enumerator_agent),
        ("exfil_analyst", exfil_analyst_agent),
        ("nist_mapper",   nist_mapper_agent),
        ("csv_builder",   csv_builder_agent),
    ]

    for i, (name, fn) in enumerate(agent_fns):
        meta = AGENT_LABELS[name]
        yield sse("agent_start", {"agent": name, "label": meta["label"], "desc": meta["desc"], "index": i})
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, fn, state)
            state.update(result)
            yield sse("agent_done", {
                "agent": name,
                "label": meta["label"],
                "index": i,
                "stats": _agent_stats(name, state),
            })
        except Exception as e:
            yield sse("agent_error", {"agent": name, "error": str(e)})

    # Final result
    rows = state.get("csv_rows", [])
    nist = state.get("nist_mapping", {})
    yield sse("complete", {
        "total_vectors": len(rows),
        "familles_nist": nist.get("familles_prioritaires", []),
        "resume_nist": nist.get("resume_couverture", ""),
        "warnings": state.get("orchestration_warnings", []),
        "csv_rows": rows,
        "nist_mapping": nist,
    })

def _agent_stats(name: str, state: ExfilState) -> dict:
    if name == "normalizer":
        n = state.get("normalized", {})
        return {"asset": n.get("asset", ""), "interfaces": len(n.get("interfaces", []))}
    if name == "surface_enum":
        return {"surfaces": len(state.get("surfaces", []))}
    if name == "exfil_analyst":
        return {"vectors": len(state.get("exfil_vectors", []))}
    if name == "nist_mapper":
        return {"familles": state.get("nist_mapping", {}).get("familles_prioritaires", [])}
    if name == "csv_builder":
        return {"rows": len(state.get("csv_rows", []))}
    return {}

@app.get("/analyze/stream")
async def analyze_stream(objet_it: str):
    return StreamingResponse(
        run_swarm_stream(objet_it),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.get("/csv/{objet_it}")
async def download_csv(objet_it: str):
    """Re-run swarm and return CSV (for direct download)."""
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: swarm.invoke({"raw_submission": objet_it, "orchestration_warnings": []}),
    )
    rows = result.get("csv_rows", [])
    if not rows:
        return JSONResponse({"error": "No rows generated"}, status_code=500)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["env", "detail_de_surface", "technique_exploitee", "explication_technique"])
    writer.writeheader()
    writer.writerows(rows)

    filename = f"registre_{objet_it.lower().replace(' ','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/health")
def health():
    return {"status": "ok"}
