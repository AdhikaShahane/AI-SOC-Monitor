# AI-SOC Monitor

AI-SOC Monitor is a small Security Operations Center (SOC) dashboard built to explore how AI can assist with security event analysis.

The application works with security events from sources such as firewalls, IDS/IPS, authentication systems and network telemetry. It uses rule-based detection to identify suspicious activity and can use Gemini to provide a second layer of analysis for events and incidents.

This is a learning and portfolio project. It is not intended to replace a production SIEM, IDS/IPS, firewall, EDR, or incident-response platform.

## What it does

* SOC-style dashboard for security events and incidents
* Synthetic firewall, IDS/IPS, authentication and network logs
* Live security-event stream for testing
* Rule-based detection and event re-processing
* Event search and filtering
* Incident creation and status tracking
* Event and incident detail views
* Gemini-assisted security analysis
* Deterministic fallback analysis when Gemini is unavailable
* JSON log export
* JSON/CSV log ingestion
* Separate firewall, IDS/IPS, authentication and network monitoring views
* Basic SOC metrics and reports

## How it works

The project keeps detection and AI analysis as two separate parts.

```text
Security events
      |
      v
Rule-based detection
      |
      +----> Normal / Suspicious events
      |
      v
Incident correlation
      |
      v
Gemini analysis (optional)
      |
      v
Analyst-facing assessment
```

The detection rules provide the initial signal. Gemini is used to help explain and assess that signal rather than being treated as the only detection mechanism.

The AI analysis can return:

* Severity
* Risk score
* Confidence
* Evidence
* Reasoning summary
* Recommended defensive actions
* Possible false-positive level
* Additional information needed

If a Gemini API key is not available, the application can use its deterministic fallback analysis so the main workflow can still be demonstrated.

## Detection focus

The current project works with scenarios including:

* Brute-force authentication activity
* Suspicious authentication sequences
* Port scanning
* Traffic anomalies
* Suspicious web requests
* Privilege-related activity
* Unusual outbound activity

The detection result depends on the telemetry available to the application. A suspicious event should not automatically be treated as proof of a successful attack or compromise.

## Tech stack

* React
* TypeScript
* Vite
* Express
* Tailwind CSS
* Google Gemini API
* Google GenAI SDK
* Lucide React
* Motion
* Node.js / tsx

## Project structure

```text
src/
├── components/
│   ├── views/
│   └── modals/
├── services/
│   ├── detectionEngine
│   ├── syntheticLogGenerator
│   ├── metricsCalculator
│   └── aiAnalystClient
├── types/
└── App.tsx

server.ts
test/
```

The structure may change as the project develops.

## Running locally

### 1. Clone the repository

```bash
git clone https://github.com/AdhikaShahane/AI-SOC-Monitor.git
cd AI-SOC-Monitor
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure Gemini

Create a `.env` file using `.env.example` as a reference:

```env
GEMINI_API_KEY=your_api_key_here
```

Do not commit the real API key to the repository.

### 4. Start the application

```bash
npm run dev
```

Open the local address shown by the development server.

## Useful commands

```bash
npm run dev      # start the application
npm run build    # build the application
npm run preview  # preview the production build
npm run lint     # TypeScript check
npm test         # run detection tests
```

## Demo workflow

A simple way to test the application:

1. Start the application.
2. Load the demo security dataset.
3. Open the SOC Dashboard.
4. Review the generated events.
5. Check the Firewall, IDS/IPS, Authentication and Network sections.
6. Open a suspicious event.
7. Run AI analysis if Gemini is configured.
8. Create an incident from related events.
9. Review the incident details and recommendations.
10. Export the events if required.

## Limitations

The main demonstration currently uses synthetic security telemetry.

The application does not automatically connect to a real corporate firewall, IDS/IPS, endpoint, cloud account or network.

It also does not currently provide:

* Enterprise-scale log storage
* A full SIEM pipeline
* Built-in threat-intelligence feeds
* Endpoint agents
* Automated incident response
* Production-grade authentication and access control

The AI output is intended to assist an analyst with investigation and explanation. It should be reviewed by a human before any real-world security decision is made.

## Security considerations

Do not put real credentials, customer information, private logs or sensitive infrastructure data into a public deployment.

If real security telemetry is connected later, the application should have appropriate authentication, authorization, secret management, log sanitisation, retention controls and audit logging before being used outside a controlled environment.

## Project status

This project is being developed as a practical cybersecurity and AI project with a focus on:

* SOC monitoring
* Security log analysis
* Rule-based detection
* Incident correlation
* AI-assisted investigation
* Defensive security automation

Possible future improvements include stronger event correlation, configurable detection rules, MITRE ATT&CK mapping, persistent storage, authentication and integrations with real telemetry sources.

