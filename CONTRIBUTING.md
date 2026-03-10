# Contributing to Panguard AI

Panguard AI is MIT-licensed and open to contributions. This guide helps you get started.

---

## Development Setup

### Prerequisites

- [Node.js](https://nodejs.org/) >= 20.0.0
- [pnpm](https://pnpm.io/) >= 9.0.0

### Getting Started

```bash
git clone https://github.com/panguard-ai/panguard-ai.git
cd panguard-ai
pnpm install
pnpm build
pnpm test
```

### Useful Commands

```bash
pnpm dev              # Start all dev servers
pnpm build            # Build all packages
pnpm test             # Run all tests
pnpm typecheck        # TypeScript strict checking
pnpm lint             # ESLint + security plugin
pnpm format           # Prettier formatting
```

---

## Project Structure

This is a pnpm monorepo with 16 packages. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full dependency graph and system design.

Key directories:

```
packages/
  core/                   # Shared foundation (start here to understand the codebase)
  panguard/               # CLI entry point
  atr/                    # Agent Threat Rules (open standard)
  panguard-guard/         # Real-time monitoring engine
  panguard-scan/          # Security scanner
  panguard-mcp/           # MCP server for AI assistants
  panguard-skill-auditor/ # AI agent skill auditor
config/
  sigma-rules/            # 3,754+ Sigma detection rules
  yara-rules/             # 4,369+ YARA detection rules
```

---

## Making Changes

### Branch Naming

```
feature/short-description    # New features
fix/short-description        # Bug fixes
docs/short-description       # Documentation
rules/short-description      # Detection rules
```

### Commit Messages

We use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add Discord notification channel
fix: handle empty SKILL.md gracefully
docs: update ATR rule writing guide
test: add E2E tests for skill auditor pipeline
refactor: extract rule loader from guard engine
chore: update sigma rules to latest community release
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

### Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with tests
4. Ensure all checks pass: `pnpm build && pnpm test && pnpm typecheck && pnpm lint`
5. Submit a PR with a clear description of what and why
6. Link any related issues

---

## Testing

- **Framework:** Vitest 3 with v8 coverage
- **Minimum coverage:** 80% for new code
- **Write tests first** when possible (TDD)

```bash
pnpm test                    # Run all tests
pnpm test -- --watch         # Watch mode
pnpm test:coverage           # Run with coverage report
```

Test files go in `tests/` directories within each package:

```
packages/panguard-guard/
  src/
  tests/
    guard-engine.test.ts
    atr-engine.test.ts
```

---

## Code Style

- **TypeScript strict mode** -- No `any`, no implicit returns, no unused variables
- **Immutable patterns** -- Create new objects instead of mutating existing ones
- **Small functions** -- Under 50 lines per function
- **Small files** -- Under 800 lines per file, prefer many small files
- **No emojis in code** -- Use Lucide icons or custom SVG components
- **Error handling** -- Handle errors explicitly at every level, never silently swallow
- **Input validation** -- Validate at system boundaries (user input, external APIs, file content)

---

## Contributing Detection Rules

There are three ways to contribute detection rules:

### ATR Rules (AI Agent Threats)

ATR is the primary differentiator. See [packages/atr/CONTRIBUTING.md](packages/atr/CONTRIBUTING.md) for the complete guide.

Quick version:

```bash
# Validate a rule
npx agent-threat-rules validate path/to/my-rule.yaml

# Test a rule
npx agent-threat-rules test path/to/my-rule.yaml
```

Rules go in `packages/atr/rules/<category>/`. Categories: `prompt-injection`, `tool-poisoning`, `context-exfiltration`, `agent-manipulation`, `privilege-escalation`, `excessive-autonomy`, `skill-compromise`, `data-poisoning`, `model-security`.

### Sigma Rules (Network/System Threats)

Community Sigma rules go in `config/sigma-rules/custom/`. Follow the [Sigma specification](https://sigmahq.io/).

### YARA Rules (File/Malware Threats)

Community YARA rules go in `config/yara-rules/custom/`. Follow the [YARA documentation](https://yara.readthedocs.io/).

---

## Contributing Translations

The website uses [next-intl](https://next-intl-docs.vercel.app/) with two locales:

- English: `packages/website/messages/en.json`
- Traditional Chinese: `packages/website/messages/zh.json`

To add or improve translations, edit the corresponding JSON file. Keys must match between both files. Some strings use ICU format for dynamic values (e.g., `{sigmaRules}`).

---

## Security Issues

Report security vulnerabilities privately. See [SECURITY.md](SECURITY.md) for the disclosure process. Do not open public issues for security bugs.

---

## Recognition

Contributors are credited through:

- Git commit history and PR attribution
- `author` field in ATR rules you write
- Release notes for significant contributions

---

## License

All contributions are licensed under MIT. By submitting a PR, you agree to license your contribution under MIT. No CLA required.
