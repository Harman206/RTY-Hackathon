# 🚀 Buildathon: Make Wednesdays Great Again

**Masters' Union · For AI Developers · Winner gets Rs. 25,000**

> **Every team must build in a fork of this repository.** Projects not built in a fork of this repo won't be judged.

| | |
|---|---|
| **Date** | Wednesday, 18 November 2026 |
| **Hacking** | **3:00 PM – 7:00 PM IST** (code freeze at 7:00 PM sharp) |
| **Venue** | CDS Audi, 8th floor |
| **Prize** | Rs. 25,000 to the winning team |
| **Register your fork** | 👉 **[https://forms.gle/ZJUYKwTYjsMsVB2b9](https://forms.gle/ZJUYKwTYjsMsVB2b9)** (**deadline 3:30 PM IST**) |
| **Final submission** | Your fork as it stands at **7:00 PM IST**. There's nothing else to submit. |

> 🤖 **Using an AI coding agent?** Point it at [`AGENTS.md`](AGENTS.md). It has the full event brief, tracks, judging and rules in a form agents can read directly. Claude Code loads it automatically through `CLAUDE.md`, and Codex reads `AGENTS.md` natively.

---

## 🎯 Pick one build track

| # | Track | Brief |
|---|---|---|
| **01** | **Build for the Physical World** | Make a real-world task easier, faster or more reliable. Show it in a realistic scenario. |
| **02** | **Build for AI Agents** | Find something an agent struggles with. Build the tool that fixes it, then demo the agent using it. |
| **03** | **Build in Your Area of Expertise** | Pick a field you know firsthand. Ship a working product that improves how people handle it today. |

## ⚖️ How you'll be judged (each criterion is ⅓ of your score)

| Criterion | The question judges ask |
|---|---|
| **Working product** | Does it do what you say it does? Show the core workflow in your demo. |
| **Problem insight** | Who faces this problem, and why does it happen? |
| **Depth of execution** | How well did you solve the hardest part of the build? |

---

## Why fork this repo?

Everyone starts from the same commit (the **genesis commit**) at the same time. Organizers can then check that:
- all code was written **during** the Buildathon and not brought in from an earlier project,
- teams commit steadily instead of pasting in one huge AI-generated dump at the end,
- every repo stays public and visible while you build.

The organizers track every fork automatically: commits, timing and activity. Read [RULES.md](RULES.md) before you write any code.

---

## ✅ Setup (about 5 minutes, do it at 3:00 PM)

**In short:** fork → register your fork in the form **by 3:30 PM** → build → push before 7:00 PM.

### 1. Fork this repo
Click **Fork** (top right). On the fork screen:
- **Owner:** one team member's personal account. Only **one fork per team**.
- **Repository name:** `buildathon-<team-name>`, for example `buildathon-byte-bandits`
- Click **Create fork**.

> ⚠️ Don't download a ZIP or copy the files into a new repo. **It has to be a real GitHub fork**, or the tracker can't see you.

### 2. Keep it public
Forks of a public repo are public. **Don't make it private, archive it, or delete it** until judging is over.

### 3. Add your teammates
In your fork: **Settings → Collaborators → Add people**. Add each teammate's GitHub account so their commits count toward the team.

### 4. Enable Actions
Open the **Actions** tab of your fork and click **"I understand my workflows, go ahead and enable them"**. This runs the automatic check on every push.

### 5. Make your registration commit (your first commit)
Fill in [`team.json`](team.json). `track` must be one of `physical-world`, `ai-agents` or `area-of-expertise`. Then:

```bash
git clone https://github.com/<your-username>/buildathon-<team-name>.git
cd buildathon-<team-name>
# edit team.json
git add team.json
git commit -m "register: <team name>"
git push
```

The **Hackathon check** in the Actions tab should go green ✅. If it's red, open the run to see what's wrong in `team.json`.

### 6. Register your fork (deadline: 3:30 PM IST)
👉 **[https://forms.gle/ZJUYKwTYjsMsVB2b9](https://forms.gle/ZJUYKwTYjsMsVB2b9)**

It's a 4-question Google Form: team name, fork link, track, team members. It connects your repo to the organizers' live tracker.

- Fill it in **once per team**, right after forking, and **no later than 3:30 PM IST**. **Teams that don't register can't be tracked.**
- Paste your **fork's** URL (`https://github.com/<you>/buildathon-<team-name>`), not this starter repo's.
- Need to change something? Use the **"Edit your response"** link on the confirmation page. Don't fill it in twice.
- **Final submission is automatic.** Whatever is pushed to your fork at 7:00 PM IST is what gets judged.

---

## 🛠 While you build (3:00 – 7:00 PM)

- Put your code anywhere in the repo (`app/`, `src/`, `frontend/`, `backend/`…). There's no required layout.
- **Commit early, commit often**, at least every 30 minutes of real work, with messages that say what changed.
- **Push regularly.** Commits you never push don't exist to the tracker.
- AI coding tools (Claude Code, Codex, Cursor, Copilot…) are **allowed and encouraged**. Keep `AGENTS.md` and `CLAUDE.md` in the repo; they keep your agent within the rules.
- Before 7:00 PM, replace the "Your project" section below with your project's README.

## 🧊 Code freeze: 7:00 PM IST

At 7:00 PM the tracker takes a snapshot of every fork. **Commits pushed after code freeze are ignored.** Judges look at your last commit before 7:00 PM.

## ❌ Things that get you flagged

- Rewriting history (`git push --force`, rebasing away the genesis commit, squashing everything into one commit)
- Commits dated before 3:00 PM
- One or two giant commits containing most of the project
- A repo that isn't a fork of this one, or that's private or deleted

See [RULES.md](RULES.md) for the full list.

---

## Your project

### AI Compliance Engine

Paste in a new regulation and a JSON snapshot of how the company is set up today. The engine lists every gap, each tied to a verbatim quote from the regulation, and writes a formal, audit-ready compliance log.

- **Team:** _TODO_
- **Track:** _TODO_ (`area-of-expertise` fits regulatory compliance)
- **Problem:** Compliance officers and internal auditors at regulated companies (fintech, health, SaaS handling personal data) have to work out, by hand, what each new or amended regulation means for their current policies and systems. They read dense legal text clause by clause, compare it with retention settings, breach procedures and access reviews spread across teams, and then document the findings in a format an auditor or regulator will accept. It happens because regulations change faster than teams can re-read them. Obligations are buried in prose, and the record of who found what, and when, gets written up after the fact.
- **What we built:** two pure-Python functions that an API layer imports. `analyze_compliance_gap(regulation_text, company_state)` returns structured, severity-sorted findings (`ANOM-001`…), and `generate_audit_trail(findings)` returns a Markdown audit log with an executive summary, a findings table, remediation plans and a timestamped audit trail.
- **The hardest part:** making LLM output reliable enough to put in an audit file.
  - **Schema-constrained output:** JSON-schema structured outputs, then pydantic validation, then up to 3 retries.
  - **Hardened JSON parsing:** fenced, double-encoded or prose-wrapped JSON is repaired before parsing.
  - **Grounded excerpts:** every `regulation_excerpt` is matched back to the source text and replaced with an exact substring, so quotes are never invented.
  - **Dates set by Python:** all timestamps come from Python in UTC. The audit log is rejected if the model writes any date or time that isn't in the input.
  - **Fallback renderer:** if the model's log fails validation twice, a deterministic renderer produces a valid log anyway.
  - **Prompt-injection defense:** regulation and company text are treated as untrusted data.
- **Bring your own key:** every function takes an optional `api_key=`, so each user can run the engine on their own Anthropic key. Without it, the engine uses `ANTHROPIC_API_KEY`.

### Setup and run

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export ANTHROPIC_API_KEY=...          # or pass api_key= per call
python ai_engine.py                   # smoke test: 30-day vs 90-day retention example
pytest -m "not live"                  # offline suite, no key or network needed
pytest -m live                        # real API: retention gap, compliant state, prompt injection, 20x reliability loop
```

| Env var | Default | Notes |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | none | Required unless the caller passes `api_key=`. Read at call time and never logged. |
| `LLM_MODEL` | `claude-sonnet-5-5` | |
| `LLM_TIMEOUT_SECONDS` | `60` | Per-read timeout. Requests are streamed. |
| `LLM_EFFORT` | `medium` | `low` to `max`. |

### API

```bash
uvicorn main:app --reload          # http://127.0.0.1:8000/docs
```

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| GET | `/health` | none | `{"status": "ok"}` |
| GET | `/api/system-state` | none | the mock company profile (`mock_db.py`) |
| POST | `/api/analyze-regulation` | `{"text": "...", "company_state": {...}?}` | list of anomalies |
| POST | `/api/generate-audit` | `{"anomalies": [...]}` or `{"text": "...", "company_state": {...}?}` | `{"anomalies": [...], "markdown": "..."}` |

- Send the user's own key in the optional `X-Anthropic-Api-Key` header.
- `company_state` defaults to the mock profile.
- Errors return a `detail.error` code:
  - **422:** `INVALID_INPUT`, for bad input.
  - **401:** `LLM_AUTH`, when the key is missing or rejected.
  - **502:** `LLM_UNAVAILABLE`, when the provider fails.

### Contract for the API layer

```python
from ai_engine import analyze_compliance_gap, generate_audit_trail, LLMError, LLMConfigError

anomalies = analyze_compliance_gap(regulation_text, company_state_dict, api_key=user_key)  # list[dict]
markdown  = generate_audit_trail(anomalies, api_key=user_key)                               # str
```

- Each anomaly has exactly these keys: `id`, `title`, `category`, `severity`, `gap_type`, `regulation_requirement`, `regulation_excerpt`, `current_state`, `gap_description` and `recommended_remediation`. The list is sorted critical → low.
- Both functions are synchronous. Call them from a plain `def` route, or use `run_in_threadpool`.
- `ValueError` means bad input (HTTP 400/422).
- `LLMConfigError` means a missing or rejected key (HTTP 401/500).
- Any other `LLMError` means the provider failed (HTTP 502).
- No other exception type escapes.
