# RELIC / AUDITAI — Agent Source of Truth

> **Version:** 1.0.0  
> **Last Updated:** 2026-01-07  
> **Purpose:** Specification & Architecture Reference for AI Agents and Developers

---

## 1. Vision & Objectifs

### 1.1 Objectif Principal

Scanner de sécurité web personnel, 100% local et dockerisé, qui analyse une URL cible et produit des rapports de sécurité enrichis par IA. Outil de portfolio/apprentissage, pas de déploiement production.

### 1.2 Objectifs Secondaires

- Scanner passif/actif avec détection de vulnérabilités (headers, TLS, cookies, CORS, XSS, SQLi)
- Streaming des logs en temps réel (SSE)
- Génération de rapports PDF professionnels via ReportLab
- Analyse IA locale (Ollama) avec fallback cloud (Groq)
- Historique des scans persisté (SQLite)
- Interface web moderne (Next.js) avec UX terminal/cyber

### 1.3 Non-Objectifs

- ❌ Multi-tenancy / gestion utilisateurs
- ❌ Déploiement cloud / production
- ❌ Scans offensifs (exploitation active)
- ❌ Intégration CI/CD externe
- ❌ Licence commerciale
- ❌ Support mobile natif

---

## 2. Stack & Composants

| Composant | Technologie | Version | Notes |
|-----------|-------------|---------|-------|
| **Frontend** | Next.js (TypeScript) | 14.x | `apps/web/` |
| **Backend API** | FastAPI (Python) | 0.100+ | `services/scanner/` |
| **Database** | SQLite | 3.x | `auditai.db` |
| **LLM Local** | Ollama | latest | `localhost:11434` |
| **LLM Cloud** | Groq | API | Fallback, `llama-3.3-70b-versatile` |
| **PDF** | ReportLab | 4.x | Génération rapports |
| **HTTP Client** | httpx | 0.27+ | Async requests |
| **ORM** | SQLModel | 0.0.14+ | Pydantic + SQLAlchemy |
| **Container** | Docker Compose | 2.x | Orchestration locale |
| **Runtime** | Python 3.11+ / Node 20+ | - | Via `.nvmrc` |

### Variables d'Environnement Clés

```bash
# AI Providers
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=gpt-oss:20b
GROQ_API_KEY=<your-key>
GROQ_MODEL=llama-3.3-70b-versatile

# Scanner Settings
SCANNER_DEFAULT_TIMEOUT=10.0
SCANNER_MAX_CRAWL_URLS=20
SCANNER_RATE_LIMIT_DELAY=0.3
```

---

## 3. Architecture

### 3.1 Diagramme ASCII

```
┌─────────────────────────────────────────────────────────────────────┐
│                           USER BROWSER                              │
│                         localhost:3000                              │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         NEXT.JS (WEB)                               │
│  apps/web/                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │  ScanForm.tsx  │  │ ScanResults.tsx│  │  History.tsx   │        │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘        │
│          │                   │                   │                  │
│          └───────────────────┼───────────────────┘                  │
│                              │                                      │
│                    /api/* (proxy routes)                            │
└─────────────────────────────┬───────────────────────────────────────┘
                              │ HTTP / SSE
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       FASTAPI (SCANNER)                             │
│  services/scanner/app/                                              │
│                                                                     │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐        │
│  │ routes.py│──▶│ engine.py│──▶│vuln_checks│──▶│ store.py │        │
│  │  (API)   │   │(ScanEngine)│  │  (Checks) │   │  (DB)    │        │
│  └────┬─────┘   └─────┬─────┘  └───────────┘   └────┬─────┘        │
│       │               │                              │              │
│       │         ┌─────▼─────┐                        │              │
│       │         │ AI Module │                        │              │
│       │         │analyzer.py│                        │              │
│       │         │clients.py │                        │              │
│       │         └─────┬─────┘                        │              │
│       │               │                              │              │
│       ▼               ▼                              ▼              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      SQLite (auditai.db)                     │   │
│  │  Tables: scan, scan_logs (in result_json), findings (inline) │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        OLLAMA (LOCAL LLM)                           │
│                       localhost:11434                               │
│   Model: gpt-oss:20b (configurable)                                 │
│   Fallback: Groq API (cloud)                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Flux Critiques

#### Flux Scan (Principal)

```
1. POST /scan {target, authorized: true, config}
   │
2. ├─ Policy Gate: validate_scan_request(target, authorized)
   │   └─ Reject if !authorized or invalid URL
   │
3. ├─ Create scan record (status: "queued")
   │
4. ├─ Launch BackgroundTask: run_scan_task()
   │   │
   │   ├─ ScanEngine.run_scan()
   │   │   ├─ DNS Resolution
   │   │   ├─ Port Scanning
   │   │   ├─ HTTP Fingerprinting
   │   │   ├─ WAF Detection
   │   │   ├─ Path Discovery (profile-based)
   │   │   ├─ Vulnerability Checks (headers, TLS, cookies, CORS, XSS, SQLi)
   │   │   ├─ Scoring & Grading
   │   │   └─ Log emission (callback)
   │   │
   │   └─ store.save_scan_result()
   │
5. └─ Return {scan_id} (200 OK)

6. Client: GET /scan/{id}/events (SSE)
   └─ Stream logs until status == "completed" | "failed"

7. Client: GET /scan/{id}
   └─ Return full ScanResult
```

#### Flux AI Analysis

```
1. POST /scan/{id}/ai-analysis?provider=groq
   │
2. ├─ Validate scan exists & completed
   │
3. ├─ Load scan result (findings, metadata)
   │
4. ├─ Build prompt (from templates: prompts/security_report_system_v1.txt)
   │   └─ Inject structured data (JSON findings)
   │
5. ├─ Call LLM (Ollama or Groq)
   │   └─ Stream response (StreamingResponse)
   │
6. ├─ Validate AI output (schema validation)
   │
7. ├─ Persist ai_analysis in scan.result_json
   │
8. └─ Return streaming text/event-stream
```

### 3.3 Points de Couplage (SPOF) & Mitigations

| SPOF | Impact | Mitigation (Mode Outil Perso) |
|------|--------|-------------------------------|
| SQLite file lock | Concurrent writes fail | Single-user, acceptable |
| Ollama unavailable | AI analysis fails | Fallback Groq (cloud) |
| Groq rate limit | AI analysis delayed | Retry with exponential backoff |
| Target unreachable | Scan fails gracefully | Timeout + error logging |
| Memory (large scans) | Process OOM | Limit path discovery profiles |

---

## 4. Feature Map

| Feature | Status | Notes |
|---------|--------|-------|
| Scan URL | ✅ | HTTP/HTTPS, hostname auto-prefix |
| Scan Profiles | ✅ | `minimal` (~13), `standard` (~50), `thorough` (~115 paths) |
| SSE Logs Streaming | ✅ | Real-time via `/scan/{id}/events` |
| Scan History | ✅ | Persisted, paginated list |
| Export JSON | ✅ | `/scan/{id}/json` |
| Export Markdown | ✅ | `/scan/{id}/markdown` (includes Tech Stack) |
| Export PDF | ✅ | `/scan/{id}/report.pdf` via ReportLab |
| AI Analysis | ✅ | Ollama + Groq fallback |
| AI Report PDF | ✅ | `/scan/{id}/ai-report.pdf` |
| **Tech Fingerprinting** | ✅ | **NEW** Frameworks, CMS, CDN, hosting, analytics detection |
| WAF Detection | ✅ | Fingerprinting common WAFs |
| Header Checks | ✅ | CSP, HSTS, X-Frame-Options, etc. |
| TLS/SSL Checks | ✅ | Certificate validation, protocol version |
| Cookie Security | ✅ | HttpOnly, Secure, SameSite |
| CORS Checks | ✅ | Misconfiguration detection |
| XSS Detection | ⚠️ | Basic reflection checks |
| SQLi Detection | ⚠️ | Time-based heuristics (false positives possible) |
| Port Scanning | ✅ | Common ports (21, 22, 80, 443, 3306, etc.) |
| Path Discovery | ✅ | Profile-based wordlists |
| User Authorization | ✅ | `authorized: true` required in request |
| Multi-user | ❌ | Not planned |
| Auth/Sessions | ❌ | Not needed (local tool) |

---

## 5. Modèle de Données (SQLite)

### 5.1 Table Principale: `scan`

```sql
CREATE TABLE scan (
    id              TEXT PRIMARY KEY,      -- UUID
    target          TEXT NOT NULL,         -- URL cible
    status          TEXT DEFAULT 'queued', -- queued | running | completed | failed
    started_at      DATETIME NOT NULL,
    finished_at     DATETIME,
    score           INTEGER,               -- 0-100
    grade           TEXT,                  -- A+ to F
    result_json     JSON,                  -- ScanResult complet (findings, logs, ai_analysis)
    logs_json       JSON,                  -- Live logs pendant le scan
    config_json     JSON                   -- Configuration utilisée
);
```

### 5.2 Structure result_json (Inline)

```json
{
  "scan_id": "uuid",
  "target": "https://example.com",
  "status": "completed",
  "score": 75,
  "grade": "B",
  "findings": [
    {
      "title": "Missing Content-Security-Policy",
      "severity": "medium",
      "category": "headers",
      "description": "...",
      "recommendation": "...",
      "evidence": "Header not present",
      "owasp_refs": ["A05:2021"],
      "confidence": "high",
      "repro_curl": "curl -I https://example.com"
    }
  ],
  "logs": [...],
  "timestamp": "2026-01-07T12:00:00Z",
  "ai_analysis": {
    "executive_summary": "...",
    "risk_assessment": "...",
    "recommendations": [...]
  }
}
```

### 5.3 Évolution Possible *(Optionnel — Entreprise)*

- Migration vers PostgreSQL pour concurrency
- Tables séparées: `findings`, `scan_logs`
- Index sur `target`, `created_at`, `severity`
- Partitioning par date pour archives

---

## 6. Structure du Repository

### 6.1 Layout Actuel

```
relic/
├── apps/
│   └── web/                       # Next.js Frontend
│       ├── app/                   # App Router pages
│       ├── components/            # React components
│       ├── lib/                   # Utilities
│       ├── package.json
│       └── Dockerfile
│
├── services/
│   └── scanner/                   # FastAPI Backend
│       ├── app/
│       │   ├── main.py            # FastAPI app entry
│       │   ├── routes.py          # API endpoints
│       │   ├── models.py          # Pydantic/SQLModel schemas
│       │   ├── store.py           # DB access layer
│       │   ├── database.py        # SQLite engine
│       │   ├── config.py          # Settings
│       │   ├── policy.py          # Authorization policy
│       │   ├── constants.py       # Enums (Severity, Category)
│       │   ├── pdf.py             # ReportLab PDF generation
│       │   ├── sse.py             # Server-Sent Events
│       │   │
│       │   ├── scanner/           # Core scanning engine
│       │   │   ├── engine.py      # ScanEngine orchestrator
│       │   │   ├── http_client.py # Async HTTP client
│       │   │   ├── crawler.py     # URL crawler
│       │   │   ├── path_discovery.py # Wordlist-based discovery
│       │   │   ├── header_checks.py
│       │   │   ├── tls_checks.py
│       │   │   ├── cookies_checks.py
│       │   │   ├── cors_checks.py
│       │   │   ├── vuln_checks.py
│       │   │   ├── xss_detector.py
│       │   │   ├── port_scanner.py
│       │   │   ├── waf_detection.py
│       │   │   ├── scope.py
│       │   │   ├── scoring.py
│       │   │   ├── models.py      # Scanner-specific models
│       │   │   └── normalizer.py
│       │   │
│       │   └── ai/                # AI analysis module
│       │       ├── analyzer.py    # Main analyzer
│       │       ├── clients.py     # Ollama/Groq clients
│       │       ├── prompt_loader.py
│       │       ├── validation.py  # Output schema validation
│       │       ├── schema.py      # AI response schemas
│       │       ├── models.py
│       │       └── prompts/       # Prompt templates
│       │           └── security_report_system_v1.txt
│       │
│       ├── tests/                 # Test suite
│       │   ├── unit/
│       │   ├── integration/
│       │   ├── performance/
│       │   ├── fixtures/
│       │   └── conftest.py
│       │
│       ├── auditai.db             # SQLite database (gitignored)
│       ├── requirements.txt
│       ├── requirements-dev.txt
│       ├── pyproject.toml
│       └── Dockerfile
│
├── docker-compose.yml             # Local orchestration
├── .env.example                   # Template env vars
├── .env                           # Local secrets (gitignored)
├── run_tests.sh                   # Test runner script
├── README.md
├── LICENSE (MIT)
└── agent.md                       # This file
```

### 6.2 Conventions

| Type | Location | Convention |
|------|----------|------------|
| **Pydantic Models** | `app/models.py`, `app/scanner/models.py`, `app/ai/models.py` | `PascalCase`, docstrings |
| **API Routes** | `app/routes.py` | FastAPI router, `snake_case` functions |
| **Prompts IA** | `app/ai/prompts/*.txt` | Plain text, versioned name |
| **Checks Scanner** | `app/scanner/*_checks.py` | `check_*` async functions |
| **Tests** | `tests/unit/test_*.py` | pytest, `test_` prefix |
| **Config** | `app/config.py` | Pydantic Settings, env vars |

---

## 7. API Contract

### 7.1 Endpoints

#### `POST /scan`

Démarre un scan de sécurité.

```http
POST /scan HTTP/1.1
Content-Type: application/json

{
  "target": "https://example.com",
  "authorized": true,
  "config": {
    "path_profile": "standard"   // minimal | standard | thorough
  }
}
```

**Response (200):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors:**
- `400` — Missing `authorized: true` or invalid URL
- `422` — Validation error

---

#### `GET /scan/{id}`

Récupère les résultats d'un scan.

```http
GET /scan/550e8400-... HTTP/1.1
```

**Response (200):** `ScanResult` (cf. section 5.2)

**Errors:**
- `404` — Scan not found

---

#### `GET /scan/{id}/events`

Stream SSE des logs en temps réel.

```http
GET /scan/550e8400-.../events HTTP/1.1
Accept: text/event-stream
```

**Response:** Server-Sent Events
```
data: {"timestamp": "...", "level": "info", "message": "Starting scan..."}

data: {"timestamp": "...", "level": "info", "message": "DNS resolved: 93.184.216.34"}

event: done
data: {"status": "completed"}
```

---

#### `GET /scan/{id}/report.pdf`

Télécharge le rapport PDF.

**Response:** `application/pdf`

---

#### `GET /scan/{id}/json`

Export JSON brut des résultats.

**Response:** `application/json`

---

#### `GET /scan/{id}/markdown`

Export Markdown des résultats.

**Response:** `text/markdown`

---

#### `POST /scan/{id}/ai-analysis`

Lance l'analyse IA (streaming).

```http
POST /scan/{id}/ai-analysis?provider=groq HTTP/1.1
```

**Query Params:**
- `provider` (optional): `ollama` | `groq` (default: auto-detect)

**Response:** `text/event-stream` (streamed AI response)

---

#### `GET /scan/{id}/ai-report.pdf`

PDF du rapport IA.

**Response:** `application/pdf`

---

#### `GET /scans`

Liste l'historique des scans.

```http
GET /scans?limit=50&offset=0 HTTP/1.1
```

**Response (200):**
```json
[
  {
    "scan_id": "...",
    "target": "https://example.com",
    "status": "completed",
    "started_at": "2026-01-07T12:00:00Z",
    "finished_at": "2026-01-07T12:01:00Z",
    "score": 75,
    "grade": "B",
    "findings_count": 5
  }
]
```

---

## 8. Sécurité (Mode Outil Perso)

### 8.1 Secrets & Configuration

- ✅ `.env` dans `.gitignore` — jamais commité
- ✅ `.env.example` avec placeholders
- ⚠️ Rotation clés API: manuelle (acceptable pour usage perso)

### 8.2 Network Binding

```yaml
# docker-compose.yml
ports:
  - "127.0.0.1:3000:3000"  # Web
  - "127.0.0.1:8000:8000"  # API
```

> **Note actuelle:** Bind sur `0.0.0.0` dans docker-compose. Pour sécuriser, préfixer `127.0.0.1:`.

### 8.3 SSRF Protection

- Pas de blocage réseau par défaut (outil personnel)
- `authorized: true` requis dans chaque requête scan
- Validation URL: HTTP/HTTPS uniquement

### 8.4 Rate Limiting & DoS Protection

```python
# config.py
MAX_REQUESTS_PER_MINUTE = 600  # Par host
RATE_LIMIT_DELAY = 0.3         # Délai entre requêtes
ERROR_THRESHOLD = 10           # Backoff après N erreurs
LATENCY_THRESHOLD = 2.0        # Backoff si latence > 2s
```

### 8.5 Concurrency Control

```python
# routes.py (pattern recommandé)
MAX_CONCURRENT_SCANS = 3
scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

async with scan_semaphore:
    await engine.run_scan(...)
```

> **Status actuel:** Pas de semaphore explicite. À implémenter.

### 8.6 Timeouts

```python
# config.py
DEFAULT_TIMEOUT = 10.0   # HTTP requests
PORT_SCAN_TIMEOUT = 1.0  # Per port
```

### 8.7 AI Prompt Safety

- ✅ Données structurées (JSON) injectées, pas de concaténation libre
- ✅ Troncature des payloads longs (évite token overflow)
- ✅ Validation du schéma de sortie (`ai/validation.py`)
- ⚠️ Pas de sandboxing LLM (acceptable localement)

---

## 9. Qualité & Tests

### 9.1 Stratégie

| Type | Scope | Outils |
|------|-------|--------|
| **Unit** | Functions, classes | pytest, pytest-asyncio |
| **Integration** | API endpoints, DB | pytest, httpx.AsyncClient |
| **E2E** | Full scan flow | Manuel pour l'instant |
| **Performance** | Load testing | Basique (pas prioritaire) |

### 9.2 Structure Tests

```
tests/
├── unit/
│   ├── test_header_checks.py
│   ├── test_tls_checks.py
│   ├── test_cookies_checks.py
│   ├── test_cors_checks.py
│   ├── test_normalizer.py
│   ├── test_ssl_validator.py
│   └── ...
├── integration/
│   ├── test_scan_flow.py
│   └── test_api_routes.py
├── performance/
│   └── test_load.py
├── fixtures/
│   └── sample_responses.json
└── conftest.py
```

### 9.3 Lint & Format

```bash
# Python
ruff check app/ tests/
ruff format app/ tests/

# TypeScript (frontend)
npm run lint     # ESLint
npm run format   # Prettier (si configuré)
```

### 9.4 Lancer les Tests

```bash
# Depuis services/scanner/
./../../run_tests.sh

# Ou directement
cd services/scanner
pytest tests/ -v --cov=app --cov-report=html
```

---

## 10. Runbook Dev — Commandes Utiles

### Stack Complète (Docker)

```bash
# Démarrer tout
docker compose up --build

# Background mode
docker compose up -d

# Logs live
docker compose logs -f

# Stop
docker compose down

# Rebuild images
docker compose build --no-cache
```

### Backend Seul (Dev)

```bash
cd services/scanner

# Créer venv
python -m venv .venv
source .venv/bin/activate

# Installer deps
pip install -r requirements.txt -r requirements-dev.txt

# Lancer FastAPI (hot reload)
uvicorn app.main:app --reload --port 8000

# Avec variables d'env
GROQ_API_KEY=xxx uvicorn app.main:app --reload
```

### Frontend Seul (Dev)

```bash
cd apps/web

# Installer deps
npm install

# Dev server
npm run dev

# Build production
npm run build
```

### Tests

```bash
# Tous les tests
cd services/scanner && pytest tests/ -v

# Avec coverage
pytest tests/ -v --cov=app --cov-report=term-missing

# Tests unitaires seulement
pytest tests/unit/ -v

# Test spécifique
pytest tests/unit/test_header_checks.py -v
```

### Database

```bash
# Reset DB (supprime et recrée)
rm services/scanner/auditai.db
# Relancer le backend pour recréer les tables

# Inspecter DB
sqlite3 services/scanner/auditai.db
sqlite> .tables
sqlite> SELECT id, target, status, score FROM scan ORDER BY started_at DESC LIMIT 10;
```

### Ollama (Local LLM)

```bash
# Installer Ollama
brew install ollama  # macOS

# Démarrer le service
ollama serve

# Pull un modèle
ollama pull llama3.2:3b
ollama pull gpt-oss:20b

# Tester
curl http://localhost:11434/api/generate -d '{"model": "llama3.2:3b", "prompt": "Hello"}'
```

---

## 11. Roadmap Perso (Priorisée)

### 🔥 Maintenant (48h)

| Priorité | Tâche | Impact |
|----------|-------|--------|
| P0 | Fix SQLi false positives (time-based heuristics) | Credibility |
| P0 | Add semaphore for concurrent scan limit | Stability |
| P1 | Improve XSS detection (DOM-based checks) | Coverage |
| P1 | Add evidence hash to all findings | Credibility |
| P2 | Unit tests for `vuln_checks.py` (80%+ coverage) | Quality |

### 📅 Semaine Prochaine (2 semaines)

| Priorité | Tâche | Impact |
|----------|-------|--------|
| P1 | Implement retry logic for AI providers | Reliability |
| P1 | Add CVSS scoring to findings | Professionalism |
| P2 | Create integration test suite with mock targets | Quality |
| P2 | Add `repro_curl` generation for all vuln checks | Credibility |
| P3 | Improve PDF report layout (charts, better formatting) | UX |

### 🗓️ Plus Tard (1-2 mois)

| Priorité | Tâche | Impact |
|----------|-------|--------|
| P2 | Add JavaScript analysis (inline scripts, eval) | Coverage |
| P2 | Implement subdomain enumeration | Features |
| P3 | Add CI/CD pipeline (GitHub Actions) | DX |
| P3 | Create scan comparison feature (before/after) | UX |
| **Optionnel** | Migrate to PostgreSQL | Scalability |
| **Optionnel** | Add authentication (if multi-user needed) | Enterprise |
| **Optionnel** | Kubernetes deployment | Enterprise |

---

## 12. Références

- **Repository:** Local only
- **License:** MIT
- **OWASP Top 10:** https://owasp.org/Top10/
- **Ollama:** https://ollama.ai
- **Groq:** https://console.groq.com
- **FastAPI:** https://fastapi.tiangolo.com
- **Next.js:** https://nextjs.org/docs

---

*Ce document est la source de vérité pour le projet RELIC/AUDITAI. Toute modification d'architecture ou d'API doit être reflétée ici.*
