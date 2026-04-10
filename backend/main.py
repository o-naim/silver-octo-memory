"""
Swarm Exfiltration API — FastAPI backend
Schema: environnement / surface / detail_de_surface / technique_exploitee / explication_technique
Auto-retry on Groq 429 TPM + automatic model fallback on TPD daily limit or decommissioned model.
"""

from dotenv import load_dotenv
load_dotenv()

import os
import re
import json
import csv
import io
import time
import asyncio
from datetime import datetime
from typing import AsyncGenerator, TypedDict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse

from langchain_groq import ChatGroq
from langgraph.graph import StateGraph, START, END
from pinecone import Pinecone
from groq import RateLimitError, BadRequestError
import requests as http_requests

# ── Config ────────────────────────────────────────────────────────────────────
GROQ_API_KEY     = os.getenv("GROQ_API_KEY")
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
HF_API_KEY       = os.getenv("HF_API_KEY")
PINECONE_INDEX   = os.getenv("PINECONE_INDEX", "threat-vectors")
HF_MODEL         = "BAAI/bge-large-en-v1.5"
HF_API_URL       = f"https://router.huggingface.co/hf-inference/models/{HF_MODEL}/pipeline/feature-extraction"

# ── Model fallback chain (all active as of April 2026) ───────────────────────
MODEL_CHAIN = [
    "llama-3.3-70b-versatile",   # primary — best quality
    "qwen-qwq-32b",              # fallback 1 — strong reasoning, separate quota
    "llama-3.1-8b-instant",      # fallback 2 — fast, very high limits
]

def make_llm_json(model: str):
    llm = ChatGroq(model=model, api_key=GROQ_API_KEY, temperature=0.2)
    return llm.bind(response_format={"type": "json_object"})

_model_index = 0
llm_json = make_llm_json(MODEL_CHAIN[_model_index])

pc    = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index(PINECONE_INDEX)

# ── Retry wrapper ─────────────────────────────────────────────────────────────
def _next_model():
    """Switch to the next model in the fallback chain."""
    global _model_index, llm_json
    _model_index += 1
    if _model_index >= len(MODEL_CHAIN):
        raise RuntimeError(
            "All Groq models exhausted (daily limits or decommissioned). "
            "Try again tomorrow or add more models to MODEL_CHAIN."
        )
    next_model = MODEL_CHAIN[_model_index]
    print(f"[Model switch] Now using: {next_model}")
    llm_json = make_llm_json(next_model)


def invoke_with_retry(messages, max_retries=8, default_wait=15):
    """Invoke llm_json with:
    - automatic model switch on daily limit (TPD) or decommissioned (400)
    - sleep+retry on per-minute limit (TPM)
    """
    global llm_json
    for attempt in range(max_retries):
        try:
            return llm_json.invoke(messages)

        except RateLimitError as e:
            err_str = str(e)
            # Daily token limit — switch model immediately
            if "per day" in err_str or "TPD" in err_str:
                print(f"[Daily limit hit] Switching model...")
                _next_model()
                continue  # retry immediately with new model
            # Per-minute limit — wait then retry
            if attempt == max_retries - 1:
                raise
            try:
                match = re.search(r'try again in (\d+\.?\d*)s', err_str)
                wait_time = float(match.group(1)) + 3 if match else default_wait
            except Exception:
                wait_time = default_wait
            print(f"[TPM limit] Waiting {wait_time:.1f}s — retry {attempt + 1}/{max_retries} "
                  f"(model: {MODEL_CHAIN[_model_index]})")
            time.sleep(wait_time)

        except BadRequestError as e:
            err_str = str(e)
            # Decommissioned model — switch immediately
            if "decommissioned" in err_str or "model_decommissioned" in err_str:
                print(f"[Decommissioned] {MODEL_CHAIN[_model_index]} — switching model...")
                _next_model()
                continue
            raise  # other 400 errors — re-raise

    raise RuntimeError("Max retries exceeded")

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

# ══════════════════════════════════════════════════════════════════════════════
# AGENT PROMPTS
# ══════════════════════════════════════════════════════════════════════════════

NORMALIZER_SYSTEM = """Tu es un agent de normalisation specialise en cybersecurite.
On te donne un objet IT brut (ex: "laptop", "cle USB", "smartphone BYOD", "agent IA").

Produis un JSON structure avec :
- asset: nom canonique en francais
- asset_type: categorie (endpoint, removable_media, mobile, network_device, cloud_service, iot, peripheral, ai_agent)
- environnements_operationnels: liste des contextes d'utilisation REELS de cet asset, pas les phases SDLC.
  Exemples corrects: ["Poste de travail entreprise", "Teletravail VPN", "Environnement cloud AWS",
  "Endpoint Linux serveur", "Reseau industriel OT", "Poste developpeur avec agent IA"]
  PAS: ["production", "staging", "development"] — ce sont des phases SDLC, pas des contextes operationnels.
- interfaces: liste EXHAUSTIVE des interfaces physiques et logiques
- os_platforms: systemes exploitation possibles
- connectivity: types de connectivite reseau
- data_zones: types de donnees accessibles (Fichiers locaux, Email, Cloud sync, Cache navigateur,
  Clipboard, RAM, Registres, Logs, Secrets/tokens)

Retourne UNIQUEMENT du JSON valide, pas de markdown."""


SURFACE_SYSTEM = """Tu es un agent d'enumeration de surfaces d'exfiltration.
On te donne un objet IT normalise avec ses interfaces et contextes operationnels,
ainsi que du contexte de renseignement sur les menaces (Pinecone RAG).

Produis une liste JSON exhaustive de surfaces exploitables pour l'EXFILTRATION.
Chaque surface est un objet avec EXACTEMENT ces champs :

- environnement: (string) Le contexte operationnel / host context de la surface.
  IMPORTANT: ce champ decrit OU se trouve la surface, pas une phase SDLC.
  Exemples corrects:
    "Poste de travail entreprise"
    "Endpoint Linux - serveur d'application"
    "Cloud AWS - bucket S3"
    "Poste developpeur - Agent IA (Cursor, Claude Code, Copilot)"
    "Environnement mobile BYOD"
    "Reseau d'entreprise - DMZ"
  PAS "production", PAS "staging", PAS "development".

- surface: (string) La famille / canal / plateforme / medium de haut niveau.
  C'est le NOM de la chose exploitee — service, protocole, composant, peripherique.
  Exemples: "S3 Bucket", "Protocole DNS", "Port USB", "Connecteur MCP", "Outlook O365",
  "Assistant de code IA", "Webhook sortant", "Bluetooth OBEX", "Imprimante reseau",
  "Partage ecran Zoom/Teams", "Synchronisation OneDrive personnel"

- surface_id: identifiant court snake_case (ex: "DNS_TUNNEL", "S3_BUCKET", "MCP_CONNECTOR")

- detail_de_surface: (string) Description precise et technique du composant/service/mecanisme.
  Ce champ decrit LA CHOSE, pas l'action d'attaque.
  Exemples corrects:
    "Service de messagerie Outlook entreprise — protocole SMTP/IMAP/EWS expose"
    "Protocole DNS UDP/53 — requetes de resolution de noms sortantes non inspectees"
    "Serveur MCP externe accessible via endpoint HTTP/SSE tiers non controle"
    "Port sortant non filtre (443/80) — trafic HTTPS sortant vers internet public"
    "Extension ou plugin d'assistant de code avec acces au systeme de fichiers local"
    "Bucket S3 public mal configure — ACL autorisant lectures anonymes"
  PAS: "Exfiltration Over DNS", PAS: "Protocol Tunneling" — ce sont des noms de technique.

- categorie: une de [physique, sans_fil, reseau, logiciel, visuel, audio, cloud, social, ia]
- interfaces_liees: interfaces de l'objet liees a cette surface

Regles :
- Couvre TOUTES les categories : ports physiques, radios (WiFi, BT, NFC, cellulaire),
  ecran (capture, photo, shoulder surfing), audio (micro, dictaphone),
  stockage amovible, cloud sync, email, impression, canaux caches (DNS, ICMP, HTTPS covert),
  steganographie, exfiltration par IA/LLM/agent, copier-coller, partage ecran,
  connecteurs MCP, webhooks, APIs tierces
- Pour chaque contexte operationnel pertinent, cree des entrees distinctes
- Minimum 20 surfaces pour un laptop, 15 pour un mobile, 10 pour un USB
- Retourne JSON avec la cle "surfaces" contenant la liste
- UNIQUEMENT du JSON valide

Contexte RAG :
{rag_context}"""


EXFIL_SYSTEM = """Tu es un analyste expert en exfiltration de donnees et menaces internes (insider threats).
On te donne une liste de surfaces d'attaque avec leurs contextes operationnels.

Pour CHAQUE surface, identifie toutes les techniques d'exfiltration possibles.
Produis une liste JSON ou chaque entree a EXACTEMENT ces 5 champs :

- environnement: (string) Copie exacte du champ "environnement" de la surface.
  Ex: "Poste de travail entreprise", "Cloud AWS - bucket S3", "Endpoint Linux"
  JAMAIS "production", JAMAIS "staging", JAMAIS "development".

- surface: (string) Copie exacte du champ "surface" de la surface.
  Ex: "Protocole DNS", "S3 Bucket", "Assistant de code IA"

- detail_de_surface: (string) Copie exacte du champ "detail_de_surface".
  C'est la description du composant/service — PAS un nom de technique d'attaque.

- technique_exploitee: (string) Technique d'exfiltration specifique avec action en francais.
  Utilise des phrases d'action : "Envoyer", "Transferer", "Synchroniser", "Coller", "Exporter".
  Indique si porte officielle (fonctionnalite detournee) ou porte derobee (backdoor/implant).
  Reference MITRE ATT&CK ID si applicable (ex: T1048.003).
  Exemples:
    "Transferer des fichiers confidentiels via DNS tunneling (T1048.003) — canal cache"
    "Synchroniser le repertoire de travail vers OneDrive personnel non autorise (T1567.002)"
    "Coller des donnees sensibles dans un assistant IA cloud (ChatGPT, Claude) — porte officielle detournee"

- explication_technique: (string) Explication detaillee de 4 a 6 phrases dans le style du registre.
  Structure obligatoire :
  1. QUI agit : "La menace interne..." ou "L'agent IA..." ou "Un attaquant avec acces..."
  2. CE QUI EST UTILISE : outil, protocole, service, composant specifique
  3. CE QUI QUITTE L'ENVIRONNEMENT : type de donnees, secrets, fichiers, credentials
  4. COMMENT cela contourne les controles ou devient accessible exterieurement
  5. DIFFICULTE DE DETECTION : pourquoi c'est difficile a detecter

Regles :
- UNE technique = UNE entree. Si une surface a 4 techniques, 4 entrees distinctes.
- Minimum 30 techniques pour un laptop, 20 pour un mobile, 12 pour un USB
- Retourne JSON avec la cle "vectors" contenant la liste
- UNIQUEMENT du JSON valide

Contexte ATT&CK / CVE :
{rag_context}"""


NIST_EXFIL_SYSTEM = """Tu es un agent de mapping NIST 800-53 specialise en prevention d'exfiltration.
On te donne une liste de techniques d'exfiltration identifiees.

Produis un JSON avec exactement ces cles :
- controls_par_vecteur: dict (cle=technique courte, valeur=liste controles NIST ex ["AC-3", "SC-7"])
- familles_prioritaires: liste de 5 strings (ex ["AC", "SC", "MP", "AU", "SI"])
- resume_couverture: UNE STRING SIMPLE en francais, 3 a 4 phrases.
  IMPORTANT: ce champ est une STRING, PAS un objet, PAS un dict.

UNIQUEMENT du JSON valide."""

# ══════════════════════════════════════════════════════════════════════════════
# AGENTS
# ══════════════════════════════════════════════════════════════════════════════

def normalizer_agent(state: ExfilState) -> dict:
    r = invoke_with_retry([
        ("system", NORMALIZER_SYSTEM),
        ("human",  f"Objet IT a analyser : {state['raw_submission']}"),
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
        q = (f"data exfiltration techniques {norm.get('asset','')} "
             f"{norm.get('asset_type','')} {' '.join(norm.get('interfaces',[])[:5])}")
        vec = embed(q)
        res = index.query(
            vector=vec, namespace="__default__", top_k=15, include_metadata=True,
            filter={"$or": [{"source_type": {"$eq": "technique"}},
                            {"source_type": {"$eq": "vulnerability"}}]}
        )
        if res.get("matches"):
            rag_context = json.dumps([m.get("metadata", {}) for m in res["matches"]], indent=2)
    except Exception as e:
        warnings.append(f"Pinecone RAG: {e}")

    prompt = SURFACE_SYSTEM.replace("{rag_context}", rag_context)
    r = invoke_with_retry([
        ("system", prompt),
        ("human",  f"Objet IT normalise :\n{json.dumps(norm, indent=2, ensure_ascii=False)}"),
    ])
    try:
        data = json.loads(r.content)
        surfaces = data.get("surfaces", data if isinstance(data, list) else [])
    except Exception as e:
        surfaces = []
        warnings.append(f"Surface parse failed: {e}")
    return {"surfaces": surfaces, "enrichment_context": rag_context, "orchestration_warnings": warnings}


def exfil_analyst_agent(state: ExfilState) -> dict:
    warnings = list(state.get("orchestration_warnings", []))
    prompt = EXFIL_SYSTEM.replace("{rag_context}", state.get("enrichment_context", "Aucun"))
    r = invoke_with_retry([
        ("system", prompt),
        ("human",  f"Surfaces identifiees :\n{json.dumps(state.get('surfaces', []), indent=2, ensure_ascii=False)}"),
    ])
    try:
        data = json.loads(r.content)
        vectors = data.get("vectors", data if isinstance(data, list) else [])
    except Exception as e:
        vectors = []
        warnings.append(f"Exfil analyst parse failed: {e}")
    return {"exfil_vectors": vectors, "orchestration_warnings": warnings}


def nist_mapper_agent(state: ExfilState) -> dict:
    techniques = list(set(
        v.get("technique_exploitee", "")
        for v in state.get("exfil_vectors", [])
        if v.get("technique_exploitee")
    ))
    r = invoke_with_retry([
        ("system", NIST_EXFIL_SYSTEM),
        ("human",  f"Techniques identifiees :\n{json.dumps(techniques, indent=2, ensure_ascii=False)}"),
    ])
    try:
        nist = json.loads(r.content)
        # Coerce resume_couverture to string
        rc = nist.get("resume_couverture", "")
        if isinstance(rc, dict):
            nist["resume_couverture"] = " ".join(str(v) for v in rc.values())
        elif isinstance(rc, list):
            nist["resume_couverture"] = " ".join(str(x) for x in rc)
        # Coerce familles_prioritaires to list
        fp = nist.get("familles_prioritaires", [])
        if isinstance(fp, dict):
            nist["familles_prioritaires"] = list(fp.keys())
    except Exception:
        nist = {
            "familles_prioritaires": [],
            "resume_couverture": "Indisponible",
            "controls_par_vecteur": {},
        }
    return {"nist_mapping": nist}


def csv_builder_agent(state: ExfilState) -> dict:
    rows = []
    for v in state.get("exfil_vectors", []):
        row = {
            "environnement":         v.get("environnement", v.get("env", "Non specifie")),
            "surface":               v.get("surface", ""),
            "detail_de_surface":     v.get("detail_de_surface", ""),
            "technique_exploitee":   v.get("technique_exploitee", ""),
            "explication_technique": v.get("explication_technique", ""),
        }
        if row["technique_exploitee"] and row["explication_technique"]:
            rows.append(row)
    return {"csv_rows": rows}

# ══════════════════════════════════════════════════════════════════════════════
# GRAPH
# ══════════════════════════════════════════════════════════════════════════════

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

# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="Swarm Exfiltration API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

AGENT_LABELS = {
    "normalizer":    {"label": "Normalizer",          "desc": "Normalisation de l'objet IT + contextes operationnels"},
    "surface_enum":  {"label": "Surface Enumerator",  "desc": "Enumeration surfaces (environnement / surface / detail) + RAG"},
    "exfil_analyst": {"label": "Exfiltration Analyst","desc": "Analyse vecteurs — 5 champs complets par entree"},
    "nist_mapper":   {"label": "NIST Mapper",         "desc": "Mapping NIST 800-53"},
    "csv_builder":   {"label": "CSV Builder",         "desc": "Construction du registre 5 colonnes"},
}

CSV_FIELDS = ["environnement", "surface", "detail_de_surface", "technique_exploitee", "explication_technique"]


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

    rows = state.get("csv_rows", [])
    nist = state.get("nist_mapping", {})

    familles = nist.get("familles_prioritaires", [])
    if isinstance(familles, dict):
        familles = list(familles.keys())

    resume = nist.get("resume_couverture", "")
    if not isinstance(resume, str):
        resume = str(resume)

    yield sse("complete", {
        "total_vectors": len(rows),
        "familles_nist": familles,
        "resume_nist":   resume,
        "active_model":  MODEL_CHAIN[_model_index],
        "warnings":      state.get("orchestration_warnings", []),
        "csv_rows":      rows,
        "nist_mapping":  nist,
    })


def _agent_stats(name: str, state: ExfilState) -> dict:
    if name == "normalizer":
        n = state.get("normalized", {})
        return {
            "asset": n.get("asset", ""),
            "interfaces": len(n.get("interfaces", [])),
            "contextes": len(n.get("environnements_operationnels", [])),
        }
    if name == "surface_enum":
        return {"surfaces": len(state.get("surfaces", []))}
    if name == "exfil_analyst":
        return {"vectors": len(state.get("exfil_vectors", []))}
    if name == "nist_mapper":
        fp = state.get("nist_mapping", {}).get("familles_prioritaires", [])
        if isinstance(fp, dict):
            fp = list(fp.keys())
        return {"familles": fp if isinstance(fp, list) else []}
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
    result = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: swarm.invoke({"raw_submission": objet_it, "orchestration_warnings": []}),
    )
    rows = result.get("csv_rows", [])
    if not rows:
        return JSONResponse({"error": "No rows generated"}, status_code=500)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS)
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
    return {"status": "ok", "active_model": MODEL_CHAIN[_model_index]}
