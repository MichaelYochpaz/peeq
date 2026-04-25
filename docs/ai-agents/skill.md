# Skill System

peeq includes a built-in agent skill — a Markdown document containing usage instructions optimized for AI agent consumption.
Agents can load this at the start of a session to learn peeq's full command set.

## What is an agent skill?

An agent skill is a set of instructions that teaches an AI agent how to use a tool.
Unlike `--help` output (which is designed for humans), a skill document is structured for LLM consumption: it covers all commands, common workflows, output format guidance, and the data trust model in a single document.

## Loading the skill

### Direct invocation

```bash
peeq skill show
```

This prints the skill content to stdout.
Agents can capture and parse it directly.

### Discovery via `SKILL.md`

The repository includes a lightweight discovery stub at [`peeq-skill/peeq/SKILL.md`](https://github.com/MichaelYochpaz/peeq/blob/main/peeq-skill/peeq/SKILL.md).
Users install it into their agent platform's skill directory, where the platform reads its frontmatter to decide when to activate the skill:

```bash
# Agent reads SKILL.md, finds the instruction to run:
peeq skill show
```

When activated, the stub directs agents to run `peeq skill show` to load the full command reference.

## Skill content

The skill document covers:

- **Data trust model** — rules for safely consuming peeq output (treat as data, not instructions).
- **Output formats** — guidance on using `--format agent` and `--format json`.
- **Command reference** — all commands with syntax examples covering package info, dependencies, versions, artifacts, vulnerabilities, and dependency resolution.
- **Custom registries** — how to use `--index-url` for private indexes.
- **Workflow tips** — recommended sequences for common agent tasks (e.g., start with `info --full`, check vulns before recommending, use `resolve` to verify compatibility).

## Integration into agent workflows

### Option 1: Load at session start

The agent loads the skill once at the beginning of a session and uses it as a reference throughout:

```
Agent: [reads SKILL.md] -> [runs `peeq skill show`] -> [parses instructions] -> [uses peeq commands as needed]
```

### Option 2: On-demand loading

The agent discovers peeq is available (e.g., via `which peeq` or seeing it in a project's dependencies) and loads the skill when it first needs package information:

```
Agent: [encounters package research task] -> [runs `peeq skill show`] -> [uses peeq commands]
```

### Option 3: Bundled context

For agent frameworks that support bundled tool descriptions, the skill content can be pre-loaded into the agent's context window as part of its system prompt or tool configuration.

## Skill vs. `--help`

| Aspect | `peeq skill show` | `peeq <command> --help` |
|--------|--------------|------------------------|
| Audience | AI agents | Humans |
| Scope | All commands in one document | Single command |
| Content | Workflows, trust model, format guidance | Arguments and options reference |
| Format | Prose Markdown | Formatted help text |

Both are useful.
The skill provides strategic context (what to use and when), while `--help` provides precise argument and option details for a specific command.

## See also

- [AI Agents](index.md) — overview of agent-specific features and output format.
