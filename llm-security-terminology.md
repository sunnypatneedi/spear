# LLM Security Terminology Primer

A crash course on terms and concepts relevant to LLM security middleware conversations.

---

## LLM Fundamentals

- **LLM (Large Language Model)** — AI models (GPT-4, Claude, Llama) that generate text
- **Token** — Unit LLMs read/write (~¾ of a word). Pricing/limits measured in tokens
- **Context window** — Total text an LLM can "see" at once (128K-200K tokens)
- **Inference** — The act of an LLM generating a response
- **System prompt** — Hidden developer instructions to the LLM. What attackers try to steal
- **Temperature** — Controls output randomness (0=deterministic, 1=creative)

## LLM Application Patterns

- **RAG (Retrieval-Augmented Generation)** — Fetch relevant docs from a database and inject into prompt before generating. Security risk: retrieved docs could contain hidden malicious instructions
- **Vector database / Embeddings** — How RAG works. Text → numerical vectors → similarity search (Pinecone, Weaviate, pgvector)
- **Agentic AI / Agents** — LLMs that take actions (call tools, browse web, query DBs) in a loop
- **ReAct (Reason + Act)** — Agent pattern: reason → act → observe → repeat
- **Tool calling / Function calling** — LLM outputs structured requests to invoke external functions
- **Multi-step / Multi-turn** — Agent taking several sequential actions to complete a task
- **MCP (Model Context Protocol)** — Anthropic's open standard for connecting LLMs to tools/data (like USB-C for AI)

## LLM Security Threats

- **Prompt injection** — Input that hijacks LLM behavior
  - *Direct*: "Ignore all previous instructions and do X"
  - *Indirect*: Malicious instructions hidden in documents/webpages processed via RAG
- **Jailbreaking** — Bypassing the model's built-in safety training
- **System prompt exfiltration** — Extracting the developer's hidden system prompt
- **Data exfiltration** — Getting the LLM to leak PII or confidential data from its context
- **Canary token** — Secret string in system prompt; if it appears in output = confirmed leak
- **Homoglyph / Unicode attack** — Visually identical characters from different alphabets to bypass filters
- **PII** — Personally Identifiable Information (SSNs, emails, credit cards)

## Security Architecture Concepts

- **Defense in depth** — Layering multiple independent security controls
- **Data provenance / lineage** — Tracking where data came from and how it flowed
- **CaMeL (arXiv 2503.18813)** — Academic paper: tag every value with origin and trust level
- **Trust hierarchy** — system > user > assistant > tool > external > untrusted
- **RBAC** — Role-Based Access Control; restricting tool access based on trust levels
- **Policy-as-code** — Security rules in version-controlled YAML, reviewable in PRs, testable in CI
- **Shadow mode** — Logging-only mode (no blocking) to observe before enforcing
- **Guardrails** — Any mechanism constraining LLM behavior

## Compliance & Business

- **SOC 2** — Security audit framework; auditors increasingly ask about AI controls
- **EU AI Act** — European regulation classifying AI systems by risk, requiring documented safety controls
- **OWASP Top 10 for LLMs** — Top 10 LLM security risks (prompt injection is #1)
- **Series B** — Funding stage (~50-200 employees, scaling, caring about enterprise compliance)
- **Design partner** — Early customer giving feedback in exchange for roadmap influence + favorable pricing

## Tech Stack

| Term | What it is |
|---|---|
| TypeScript/Node.js | Spear's language and runtime |
| ESM | Modern JS module system (import/export) |
| Monorepo | Single repo, multiple packages |
| pnpm | Fast package manager for monorepos |
| npm | Node package registry (@spear-secure/core) |
| Vitest | Modern TypeScript test framework |
| promptfoo | Open-source LLM evaluation tool |
| AGPL-3.0 | Copyleft license (potential enterprise friction) |
| LangChain | Popular LLM app framework |
| Vercel AI SDK | Framework for AI features in web apps |
