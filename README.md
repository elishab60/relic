# Relic / AuditAI

**Scanner de sécurité web avec interface temps réel et rapports IA.**

Ce projet est un prototype fonctionnel réalisé dans le cadre d'un test technique. Il propose une approche moderne de l'audit de sécurité : au lieu d'un simple script, l'outil expose une **interface Web réactive** pour suivre les scans en direct, tout en conservant un **CLI** robuste pour l'automatisation.

---

## Architecture & Structure du Projet

Le projet est conçu comme un monorepo moderne, séparant clairement le frontend, le backend et l'infrastructure.

```
.
├── apps/
│   └── web/               # Frontend Next.js (Interface Web)
│       ├── app/           # Pages et Routing (App Router)
│       ├── components/    # Composants React (Terminal, Logs, UI)
│       └── lib/           # Utilitaires et API client
├── services/
│   └── scanner/           # Backend Python (Cœur du système)
│       ├── app/
│       │   ├── cli.py     # Point d'entrée CLI (Command Line Interface)
│       │   ├── main.py    # Point d'entrée API (FastAPI)
│       │   ├── scanner/   # Moteur de scan (engine, checks, crawler...)
│       │   ├── ai/        # Intégration LLM (Ollama / OpenRouter)
│       │   └── pdf/       # Générateur de rapports PDF (ReportLab)
│       ├── Dockerfile     # Image Docker du scanner
│       └── requirements.txt
├── docker-compose.yml     # Orchestration des services (Web + Scanner)
└── README.md
```

**Flux de données (Pipeline de Scan) :**

```mermaid
flowchart TD
    subgraph Client ["Client Layer"]
        User([User / CLI])
        WebUI([Web Interface])
    end

    subgraph Engine ["Core Engine (Python)"]
        Orchestrator{Orchestrator}
        NetScan[Network Scanner]
        WebScan[HTTP & Vuln Scanner]
        Crawler[Crawler]
        RawData[(Raw JSON Data)]
    end

    subgraph AI ["Intelligence Layer"]
        Prompt[Prompt Engineering]
        LLM[LLM Analysis]
    end

    subgraph Output ["Reporting"]
        PDF[PDF Generator]
        Report(Final Report)
    end

    User & WebUI -->|Start Scan| Orchestrator
    Orchestrator -->|1. Recon| NetScan
    Orchestrator -->|2. Crawl| Crawler
    Orchestrator -->|3. Audit| WebScan
    NetScan & Crawler & WebScan --> RawData
    RawData -->|4. Context| Prompt
    Prompt -->|5. Inference| LLM
    LLM -->|6. Summary| PDF
    RawData -->|7. Metrics| PDF
    PDF --> Report

    style Client fill:#f9f,stroke:#333,stroke-width:2px
    style Engine fill:#bbf,stroke:#333,stroke-width:2px
    style AI fill:#bfb,stroke:#333,stroke-width:2px
    style Output fill:#fbb,stroke:#333,stroke-width:2px
```

1.  **Input** : L'utilisateur lance un scan via le Web ou le CLI.
2.  **Engine** : Le moteur Python orchestre les modules de scan (réseau, HTTP, vulnérabilités).
3.  **Streaming** : Les logs sont envoyés en temps réel au frontend via SSE (Server-Sent Events).
4.  **IA** : Les résultats bruts sont analysés par le LLM pour générer la synthèse.
5.  **Output** : Un rapport PDF complet est généré et mis à disposition.

---

## Fonctionnalités Détaillées

### 1. Interface Web (Dashboard)
C'est le point fort du projet pour l'expérience utilisateur.
- **Lancer des scans** : Saisie simple de l'URL cible.
- **Logs en temps réel** : Visualisation "Matrix-style" des actions du scanner via SSE.
- **Rapport IA intégré** : Lecture directe de la synthèse, du score et des recommandations.
- **Téléchargement PDF** : Récupération du rapport final en un clic.

### 2. Outil CLI (Command Line)
Pour l'intégration CI/CD ou l'usage serveur.
- **Scan "headless"** : Exécution complète sans interface graphique.
- **Mode Interactif** : Prompt utilisateur si aucune cible n'est fournie.
- **Rapport PDF** : Génération identique à la version Web.

### 3. Moteur de Scan (Scanner Engine)
Le cœur technique (`services/scanner`) implémente les vérifications suivantes :

*   **Reconnaissance & Infra** :
    *   Résolution DNS et vérification de la connectivité.
    *   **WAF Detection** : Détection basique des blocages (403, headers spécifiques).
    *   **Port Scan** : Vérification rapide des 12 ports les plus critiques (FTP, SSH, HTTP, HTTPS, DBs...).
    *   **Crawler** : Exploration des pages (limité à une profondeur de 2) pour découvrir la surface d'attaque.

*   **Analyse HTTP & Sécurité** :
    *   **Headers** : Vérification des en-têtes de sécurité (HSTS, CSP, X-Frame-Options...).
    *   **Cookies** : Analyse des attributs `Secure`, `HttpOnly`, `SameSite`.
    *   **TLS/SSL** : Validation du certificat, de l'émetteur et de la date d'expiration.

*   **Vulnérabilités (Vulnerability Checks)** :
    *   **Sensitive Files** : Recherche de fichiers exposés (`.env`, `.git`, backups, logs...).
    *   **XSS (Reflected)** : Détection de patterns d'injection dans les paramètres URL.
    *   **SQL Injection** : Tests basiques d'injection SQL (Time-based & Error-based).
    *   **CORS** : Détection des configurations "Wildcard" dangereuses.

*   **Intelligence Artificielle (AI Analysis)** :
    *   Synthèse exécutive en français.
    *   Calcul du Score de Sécurité (0-100) et de la Note (A-F).
    *   Top 3 des vulnérabilités avec explications vulgarisées et techniques.
    *   Recommandations de remédiation concrètes.

---

## Installation & Démarrage

La méthode recommandée est **Docker Compose** pour une stack complète et isolée.

```bash
# 1. Cloner le projet
git clone <votre-repo>
cd relic

# 2. Lancer la stack
docker compose up -d --build
```

Une fois lancé :
- **Web UI** : [http://localhost:3000](http://localhost:3000)
- **API Docs** : [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Utilisation

### Via l'Interface Web (Recommandé)
1. Ouvrez [http://localhost:3000](http://localhost:3000).
2. Entrez l'URL cible (ex: `https://webtech-104.vercel.app`).
3. Suivez l'avancement dans la console de logs.
4. Téléchargez le rapport PDF une fois l'analyse terminée.

### Via le CLI (Docker)
Utilisez le conteneur `scanner` pour lancer des audits en ligne de commande :

```bash
# Mode interactif (recommandé)
docker compose exec -it scanner python -m app.cli scan --pdf-out report.pdf
```

Pour récupérer le fichier PDF généré sur votre machine hôte :
```bash
docker compose cp scanner:/app/report.pdf ./report.pdf
```

---

## Configuration

Le projet est "batteries included". Les valeurs par défaut sont optimisées pour un usage standard.
Vous pouvez surcharger ces variables dans le `docker-compose.yml` :

| Variable | Description | Valeur par défaut |
|----------|-------------|-------------------|
| `OLLAMA_BASE_URL` | URL de l'instance Ollama (pour IA locale) | `http://localhost:11434` |
| `OLLAMA_MODEL` | Modèle Ollama à utiliser | `gpt-oss:20b` |
| `OPENROUTER_API_KEY` | Clé API pour OpenRouter (si pas d'Ollama) | *Vide* |
| `OPENROUTER_MODEL` | Modèle OpenRouter à utiliser | `x-ai/grok-4.1-fast:free` |
| `SCANNER_DEFAULT_TIMEOUT` | Timeout HTTP global (secondes) | `10.0` |

### Recommandations Matérielles (IA Locale)

L'utilisation d'Ollama en local dépend fortement de votre GPU/RAM. Voici un guide détaillé pour choisir le bon modèle :

| Configuration Type | GPU / NPU | RAM / VRAM | Modèle Conseillé | Quantization | Perf. Estimée |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Mac Studio / Pro** | M1/M2/M3 Ultra | 64Go+ | `llama3:70b` | Q4_K_M | **Excellente** (< 20s) |
| **MacBook Pro (High)** | M1/M2/M3 Max | 32Go+ | `gpt-oss:20b` | Q4_K_M | **Très Bonne** (~25s) |
| **PC Gamer (High)** | RTX 4090 / 3090 | 24Go VRAM | `gpt-oss:20b` | Q4_K_M | **Très Bonne** (~20s) |
| **MacBook Pro (Mid)** | M1/M2/M3 Pro | 16Go | `mistral:7b` / `llama3:8b` | Q5_K_M | **Bonne** (~15s) |
| **PC Gamer (Mid)** | RTX 4070 / 3060 | 12Go VRAM | `mistral:7b` / `gemma:7b` | Q5_K_M | **Bonne** (~10s) |
| **MacBook Air / PC** | M1/M2 / Integr. | 8Go | *Déconseillé en local* | - | *Lent / OOM* |

> **⚠️ Important** : Pour un rapport de sécurité pertinent, nous recommandons au minimum un modèle **7B ou 8B** (Mistral, Llama3). Les modèles plus petits (TinyLlama, Phi-2) "hallucinent" trop souvent des vulnérabilités ou ratent le contexte.
>
> **Si votre matériel est insuffisant** : Configurez `OPENROUTER_API_KEY` pour utiliser un modèle Cloud performant sans ralentir votre machine.

---

## Limites Connues

Ce projet est un prototype avancé, mais il a ses limites par rapport à des outils commerciaux :
- **Scan de ports** : Restreint à une liste fixe pour la performance, ne remplace pas un scan Nmap complet.
- **Détection** : Les checks de vulnérabilités sont basés sur des signatures et des comportements simples, sans exploitation active complexe.
- **IA** : La qualité du rapport dépend du modèle utilisé.
    - **Ollama (Local)** : Moins puissant que les modèles cloud géants (GPT-5), mais offre une **confidentialité totale des données** (aucune donnée ne quitte votre infrastructure), ce qui est crucial en contexte de cybersécurité sensible.
    - **OpenRouter (Cloud)** : Plus performant pour la synthèse, mais implique l'envoi de métadonnées de scan à un tiers.
