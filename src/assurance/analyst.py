"""
AI Analyst Engine — generates formal audit risk statements using Claude.

For each High severity finding produced by a scanner, this module calls
Claude Opus 4.7 and returns a 3-paragraph Audit Finding written in the
voice of a Big 4 Senior IT Audit Manager.

Requires ANTHROPIC_API_KEY in the project's .env file.
"""

import anthropic
from dotenv import load_dotenv

# Load .env from the project root so ANTHROPIC_API_KEY is available.
# python-dotenv is a no-op if the file does not exist, so this is safe.
load_dotenv()

# Stable role instruction cached at the system level.
# Keeping it separate from the user turn lets the model stay in character
# without repeating the persona definition inside every user message.
_SYSTEM_PROMPT = (
    "You are a Senior IT Audit Manager at a Big 4 professional services firm. "
    "You write formal audit findings for executive-level reports. "
    "Your writing is precise, objective, and grounded in industry control frameworks. "
    "Do not use bullet points or markdown headers — write in flowing, professional paragraphs."
)


def generate_risk_statement(finding_details: str) -> str:
    """Call Claude Opus 4.7 to produce a formal 3-paragraph audit finding.

    Args:
        finding_details: Plain-text description of the security misconfiguration,
                         the affected resource, severity, and relevant controls.

    Returns:
        A formal 3-paragraph audit finding suitable for an executive report.

    Raises:
        anthropic.AuthenticationError: If ANTHROPIC_API_KEY is missing or invalid.
        anthropic.APIConnectionError:  If the Anthropic API is unreachable.
    """
    # Instantiate per call so the API key is read after load_dotenv() runs.
    client = anthropic.Anthropic()

    user_prompt = (
        f"You are a Senior IT Audit Manager at a Big 4 firm. "
        f"I have found a technical misconfiguration in an AWS environment: {finding_details}. "
        "Please write a 3-paragraph Audit Finding for a formal report. "
        "Include: 1. The Condition, 2. The Potential Risk/Impact "
        "(reference a real-world data breach scenario), and "
        "3. A Recommendation for remediation. Use a formal, executive tone."
    )

    # Stream the response — audit findings are multi-paragraph and streaming
    # prevents HTTP timeouts on longer outputs. Adaptive thinking lets the
    # model reason through nuanced risk language without a fixed token budget.
    with client.messages.stream(
        model="claude-opus-4-7",
        max_tokens=2048,
        thinking={"type": "adaptive"},
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    ) as stream:
        message = stream.get_final_message()

    # Content blocks can include thinking blocks (from adaptive thinking).
    # We only want the final text response for the audit report.
    return next(block.text for block in message.content if block.type == "text")
