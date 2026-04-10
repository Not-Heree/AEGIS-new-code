# EASM AEGIS - Comprehensive Mermaid Diagrams

This document contains the exact 8 architectural diagrams required for your report, written in standard Mermaid.js syntax.

*Tip: Paste each code block into the [Mermaid Live Editor](https://mermaid.live/) to generate high-resolution PNGs for your submission.*

---

## 1. System Architecture Diagram
*Four-layer modular architecture showing Presentation -> Application -> Data Processing -> Data Storage.*

```mermaid
flowchart TD
    %% Define Styles
    style Presentation fill:#2980b9,stroke:#none,color:#fff
    style Application fill:#27ae60,stroke:#none,color:#fff
    style Processing fill:#8e44ad,stroke:#none,color:#fff
    style Storage fill:#f39c12,stroke:#none,color:#fff

    subgraph Presentation["Presentation Layer (UI/UX)"]
        Dashboard[Web Dashboard]
        TargetView[Target Management View]
        RemediationView[Remediation Tracker]
        AssetView[Asset Inventory Breakdown]
    end

    subgraph Application["Application Logic Layer (API & Routing)"]
        Router[Flask Route Handler - app.py]
        Session[Session Management]
        JSONFormatter[JSON Response Formatter]
    end

    subgraph Processing["Data Processing Layer (Intelligence Core)"]
        Orchestrator[Pipeline Orchestrator - scanner.py]
        SmartScan[Six-Tier Smart Scanner]
        RemediationHub[Remediation Engine]
        Recon[Passive Recon & OSINT Modules]
    end

    subgraph Storage["Data Storage Layer (MongoDB)"]
        TargetsDB[(Targets)]
        VulnsDB[(Vulnerabilities)]
        AssetsDB[(Subdomains & Ports)]
        HistoryDB[(Changes & Emails)]
    end

    %% Flow connections
    Presentation <--> |HTTP / JSON| Application
    Application <--> |Python Method Calls| Processing
    Processing <--> |PyMongo Operations| Storage
```

---

## 2. MongoDB Entity Relationship Diagram (ERD)
*Maps the Target document to the 5 other primary collections discovered during intelligence gathering.*

```mermaid
erDiagram
    TARGET {
        ObjectId _id PK
        string domain
        string status
        float risk_score
        int scan_phase_completed
    }
    
    SUBDOMAIN {
        ObjectId _id PK
        ObjectId target_id FK
        string subdomain
        string status
        string source
    }
    
    VULNERABILITY {
        ObjectId _id PK
        ObjectId target_id FK
        string cve_id
        float epss_score
        string cwe_id
        string severity
        string host
    }
    
    PORT {
        ObjectId _id PK
        ObjectId target_id FK
        string host
        int port
        string service
    }

    CHANGE_LOG {
        ObjectId _id PK
        ObjectId target_id FK
        string diff_type
        date timestamp
    }

    EMAIL {
        ObjectId _id PK
        ObjectId target_id FK
        string address
        string breach_status
        string source
    }

    TARGET ||--o{ SUBDOMAIN : contains
    TARGET ||--o{ VULNERABILITY : possesses
    TARGET ||--o{ PORT : exposes
    TARGET ||--o{ CHANGE_LOG : accrues
    TARGET ||--o{ EMAIL : discovers
```

---

## 3. Data Flow Diagram - Level 0 (Context)
*Represents EASM AEGIS as the central Intelligence Hub interacting with human actors, external Intelligence APIs, and external CLI binaries.*

```mermaid
flowchart LR
    %% Entities
    User((Security Analyst))
    System[EASM AEGIS Platform]
    
    %% External Data Sources (Passive APIs)
    Shodan[Shodan API]
    Censys[Censys API]
    NVD[NVD/NIST Database]
    EPSS[FIRST EPSS Model]
    CISA[CISA KEV Database]
    
    %% External Active Binaries & OSINT CLI
    Hunter[theHarvester / LeakCheck]
    Subfinder[ProjectDiscovery Subfinder]
    Naabu[ProjectDiscovery Naabu]
    Nuclei[ProjectDiscovery Nuclei]

    %% Flow
    User -->|Target Input & Scan Trigger| System
    System -.->|Aggregated Risk JSON & UX| User
    
    System <-->|Fetch Passive Recon Port/CVE Data| Shodan
    System <-->|Fetch Passive Cert/Host Data| Censys
    System <-->|Retrieve Vulnerability Context| NVD
    System <-->|Query Probability Scores| EPSS
    System <-->|Check Exploitation Status| CISA
    
    System -.->|Orchestrates Subdomain Enum| Subfinder
    System -.->|Orchestrates Port Scans| Naabu
    System -.->|Executes Template Scans| Nuclei
    System -.->|Perform Email Breach Validation| Hunter
```

---

## 4. Data Flow Diagram - Level 1 (Pipeline)
*Detailed 7-phase structural state machine describing how unstructured target data transforms into a final Logarithmic Risk Score.*

```mermaid
flowchart LR
    Target[Root Domain]
    
    subgraph Pipeline["Seven-Phase Scanning Pipeline"]
        direction TB
        P0[Phase 0: Passive Recon]
        P1[Phase 1: Subfinder]
        P2[Phase 2: Naabu Port Scan]
        P3[Phase 3: HTTPX Fingerprint]
        P4[Phase 4: Multi-Tier Nuclei Scanner]
        P5[Phase 5: Email Harvesting]
        P6[Phase 6: Risk Scaling & Diffing]
        
        P0 --> P1 --> P2 --> P3 --> P4 --> P5 --> P6
    end
    
    DB[(MongoDB Data Lake)]
    APIs((External APIs: Shodan, Censys, NVD))

    Target --> P0
    
    %% DB Interactions
    P0 -->|Writes passive data| DB
    P1 <-->|Reads passive/Writes active| DB
    P2 <-->|Skip-scan logic / Writes ports| DB
    P3 -->|Writes tech stack| DB
    P4 <-->|Reads all assets / Writes Vulns| DB
    P4 <-->|Fetches CVSS/CWE| APIs
    P5 -->|Writes breach data| DB
    P6 -.->|Updates Risk Score| DB
```

---

## 5. Use Case Diagram
*Core interactions executed by the standard Security Analyst/User against the ecosystem.*

```mermaid
flowchart LR
    User([Security User / Analyst])
    
    subgraph EASM AEGIS Platform
        UC1(Add Target Domain)
        UC2(Initiate / Resume Scan)
        UC3(View Asset Inventory)
        UC4(View Remediation Guidance)
        UC5(View Change Timeline)
        UC6(Export JSON Data)
    end
    
    Sys([External Intelligence APIs])
    Tools([External CLI Tools])

    User --> UC1
    User --> UC2
    User --> UC3
    User --> UC4
    User --> UC5
    User --> UC6
    
    UC2 --> Sys
    UC2 --> Tools
    UC4 --> Sys
```

---

## 6. Six-Tier Smart Scanning Decision Tree Flowchart
*The architectural decision matrix that assigns discovered hosts to specific Nuclei vulnerability bins to drastically reduce scan runtime.*

```mermaid
flowchart TD
    Start([Host & Intelligence Passed to Classifier])
    
    Q1{"Does OSINT report a specific CVE?"}
    T1A["[Tier 1A] CVE Verification"]
    
    Q2{"Did HTTPX detect a specific Framework (e.g. WordPress)?"}
    T1B["[Tier 1B] Technology-Targeted"]
    
    Q3{"Is a definitive, known service port open (e.g. 3306)?"}
    T2A["[Tier 2A] Port-Informed"]
    
    Q4{"Do headers reveal web technology clues?"}
    T2B["[Tier 2B] Header-Mined"]
    
    Q5{"Are any standard HTTP/S tracking ports open?"}
    T2C["[Tier 2C] Web Catch-All"]
    
    T2CNET["[Tier 2C-NET] Network Fallback"]
    
    Done([Template Assignment Complete])

    Start --> Q1
    
    Q1 -->|Yes| T1A --> Done
    Q1 -->|No| Q2
    
    Q2 -->|Yes| T1B --> Done
    Q2 -->|No| Q3
    
    Q3 -->|Yes| T2A --> Done
    Q3 -->|No| Q4
    
    Q4 -->|Yes| T2B --> Done
    Q4 -->|No| Q5
    
    Q5 -->|Yes| T2C --> Done
    Q5 -->|No| T2CNET --> Done
```

---

## 7. Remediation Enrichment Pipeline Flowchart
*Maps the robust sequence of external API validation checks, ensuring failures silently fallback to simpler severity logic seamlessly.*

```mermaid
flowchart TD
    DB[(Vuln Stored in MongoDB)]
    UI[User clicks 'View Remediation Plan']
    
    Enricher{Remediation Engine intercepts UI request}
    
    DB --> UI
    UI --> Enricher
    
    Enricher --> S1{1. Extract CVE/CWE Identifiers}
    S1 -->|No Specific ID| FallbackGen[Generic Fallback Guidance based on severity]
    
    S1 -->|Has CVE| KEV{2. Fetch CISA KEV Exploitation Status}
    
    KEV -->|API Timeout / Error| FallbackKEV[Mark KEV Unknown]
    KEV -->|Success| EPSS{3. Fetch FIRST EPSS Probability}
    FallbackKEV --> EPSS
    
    EPSS -->|API Timeout / Error| FallbackEPSS[Mark EPSS % 0]
    EPSS -->|Success| NVD{4. Fetch NVD Data & Patch Links}
    FallbackEPSS --> NVD
    
    NVD -->|API Timeout / Error| FallbackNVD[Calculate Default CVSS]
    NVD -->|Success| CWE{5. Query Local MITRE CWE Dataset}
    FallbackNVD --> CWE
    
    CWE -->|Not Found in DB| FallbackCWE[Omit Specific Action Path]
    CWE -->|Success| Score{6. Calculate Meta Priority Score}
    FallbackCWE --> Score
    FallbackGen --> Score
    
    Score --> Build[7. Compile Structured 'How To Fix' JSON]
    Build --> Render[Push HTML Context to Remediation Dashboard]
```

---

## 8. Seven-Phase Scanning Pipeline with Resumability
*Shows how the pipeline's checkpoints prevent repeating intense scanning jobs when network failures or timeouts occur.*

```mermaid
flowchart TD
    Start([Initiate Pipeline Scan])
    ReadDB[(Check MongoDB for target.scan_phase_completed)]
    
    Start --> ReadDB
    
    P0{Is scan_phase >= 0?}
    P1{Is scan_phase >= 1?}
    P2{Is scan_phase >= 2?}
    
    RunP0[Execute Phase 0: Passive Recon]
    RunP1[Execute Phase 1: Subfinder]
    RunP2[Execute Phase 2: Naabu]
    
    Save0[(Save Phase=0)]
    Save1[(Save Phase=1)]
    Save2[(Save Phase=2)]
    
    ReadDB --> P0
    
    P0 -->|No Phase Completed| RunP0 --> Save0 --> P1
    P0 -->|Yes| P1
    
    P1 -->|Phase 0 is latest| RunP1 --> Save1 --> P2
    P1 -->|Yes| P2
    
    P2 -->|Phase 1 is latest| RunP2 --> Save2
    P2 -->|Yes| Continue([Continue sequentially through Phase 6...])
    
    Save2 --> Continue
    
    Crash((Server Crash or API Timeout))
    RunP1 -.-x Crash
    
    note[On next trigger, scan_phase_completed = 0.<br/>Pipeline bypasses Phase 0 logic and cleanly resumes Phase 1.]
    Crash --- note
    
    style Crash fill:#c0392b,stroke:#none,color:#fff
    style note fill:#f1c40f,stroke:#none,color:#333
```

---

## 9. Flowchart — Change Detection Engine
*Set-difference mathematical sequence demonstrating how the backend auto-resolves patched vulnerabilities and maps new shadow IT.*

```mermaid
flowchart TD
    ScanComplete([All active scanning modules complete])
    
    DB[(MongoDB Historical Scans)]
    
    ScanComplete --> FetchOld{Fetch Previous Phase Data}
    FetchOld -->|No Previous Data| Baseline[Mark as Initial Scan / Baseline] --> Done
    FetchOld -->|Has History| DiffEngine{Initialize Change Engine}
    
    DiffEngine --> DiffSubs[Compare Subdomain Sets]
    DiffSubs -->|Current - Past| NewSubs[Log 'New Assets']
    DiffSubs -->|Past - Current| LostSubs[Log 'Lost Assets']
    
    DiffEngine --> DiffPorts[Compare TCP Port Mappings]
    DiffPorts -->|Current - Past| NewPorts[Trigger High Priority: New Exposure]
    
    DiffEngine --> DiffVulns[Compare Vulnerability Keys]
    DiffVulns -->|Current - Past| NewVulns[Log 'New Threat']
    DiffVulns -->|Past - Current| FixedVulns[Auto-Mark Status = Resolved]
    
    NewSubs -.-> Compile
    LostSubs -.-> Compile
    NewPorts -.-> Compile
    NewVulns -.-> Compile
    FixedVulns -.-> Compile
    
    Compile[Compile Change_Log Aggregate] --> DBWrite[(Write to CHANGE_LOG Collection)]
    
    DBWrite --> Done([Proceed to Phase 6])
```

---

## 10. Flowchart — Logarithmic Risk Scoring Algorithm
*A mathematical flowchart illustrating how the pipeline processes the final security grade, severely penalizing the first few critical vulnerabilities but compressing subsequent ones to prevent score inflation over 100.*

```mermaid
flowchart TD
    Start([Execute Phase 6 - Risk Engine])
    
    Vulns[(Fetch Open Vulnerabilities)]
    Exposure[(Fetch Domain Target Config)]
    Email[(Fetch Email Breach Context)]
    
    Start --> Vulns
    Start --> Exposure
    Start --> Email
    
    Vulns --> VWeight[Assign Severity Base Weights<br/>Crit=40, High=25, Med=10, Low=3]
    VWeight --> VSlim[Calculate Aggregated Vulnerability Sum 'X']
    
    VSlim --> MathEquation{"Apply Asymptotic Normalization<br/>Score = 60 * [1 - e^(-X / 80)]"}
    
    Exposure --> ETier[Calculate Exposure Modifiers<br/>+15 for Internet Facing/Prod]
    Email --> BTier[Calculate Breach Density<br/>+2 per employee breach entry, max 15]
    
    MathEquation --> ScoreCompile[Aggregate Module Sub-Scores]
    ETier --> ScoreCompile
    BTier --> ScoreCompile
    
    ScoreCompile --> MathCeil{"Ceiling Function<br/>Risk = Min(Score, 100)"}
    
    MathCeil --> DBUpdate[(Update Global TARGET Document)]
```

---

## 11. Flowchart — Priority Score Calculation Algorithm
*Maps the conditional mathematical flow for triaging an individual vulnerability based on severity, exploitability, and exposure to guarantee a dynamic 0-100 severity grade.*

```mermaid
flowchart TD
    Start([Calculate Priority Score for Vulnerability])
    Init[Base Priority Score = 0]
    
    Start --> Init
    
    Init --> F1{1. Base Severity?}
    F1 -->|Critical| Add35[+ 35 Points]
    F1 -->|High| Add25[+ 25 Points]
    F1 -->|Medium| Add15[+ 15 Points]
    F1 -->|Low| Add8[+ 8 Points]
    
    Add35 --> F2
    Add25 --> F2
    Add15 --> F2
    Add8 --> F2
    
    F2[2. CVSS Score Multiplier] --> CVSS[+ Min(CVSS_Score * 2, 20 Max)]
    
    CVSS --> F3[3. EPSS Likelihood Multiplier]
    F3 --> EPSS[+ Min(EPSS_Percent * 25, 25 Max)]
    
    EPSS --> F4{4. Actively Exploited?}
    F4 -->|Yes| KEV[+ 15 Points from CISA KEV]
    F4 -->|No| F5
    KEV --> F5
    
    F5{5. Asset Exposure}
    F5 -->|Internet Facing/Prod| Exp[+ 5 Points]
    F5 -->|Internal| Total
    Exp --> Total
    
    Total[Sum All Modifier Factors] --> MathCeil{"Ceiling Function<br/>Final_Priority = Min(Total, 100)"}
    
    MathCeil --> Done([Return Final Priority Score])
```
