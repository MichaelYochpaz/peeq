"""Output formatting layer (Pretty, Plain, Agent, JSON renderers).

Provides `Renderer` ABC with four implementations:

- `RichRenderer` --- Rich panels, tables,
  syntax highlighting for terminal output.  Auto-selected for TTY
  (`--format=pretty`).
- `PlainRenderer` --- Clean, undecorated
  text for CI pipelines, log files, and piped output.  Auto-selected
  for non-TTY (`--format=plain`).
- `AgentRenderer` --- XML-bounded
  structured text optimized for AI agent consumption.  Must be
  explicitly requested (`--format=agent`).
- `JSONRenderer` --- Structured JSON for
  programmatic use.  Must be explicitly requested (`--format=json`).

Use `get_renderer` to select the appropriate renderer based on
`--format` flag or TTY auto-detection.
"""

from peeq.output.agent import AgentRenderer
from peeq.output.base import OutputFormat, Renderer, get_renderer
from peeq.output.json import JSONRenderer
from peeq.output.plain import PlainRenderer
from peeq.output.rich import RichRenderer

__all__ = [
    "AgentRenderer",
    "JSONRenderer",
    "OutputFormat",
    "PlainRenderer",
    "Renderer",
    "RichRenderer",
    "get_renderer",
]
