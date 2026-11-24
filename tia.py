#!/usr/bin/env python3
"""Threat Intelligence Assembly Line: Scout -> Extractor -> ATT&CK Mapper.

A provider-agnostic port of the CrewAI flow. Any tool-calling chat model works:
Claude, GPT, Gemini, Qwen, OpenRouter, or a local OpenAI-compatible server.

    python tia.py "Lazarus Group" --model anthropic/claude-sonnet-5-5
    python tia.py HAFNIUM --model gemini/<model> --mapper-model openai/<model>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import warnings
from datetime import date
from pathlib import Path

import litellm
import requests
from bs4 import BeautifulSoup

from prompts import AGENTS

litellm.drop_params = True  # silently drop params a given provider does not support
litellm.suppress_debug_info = True
warnings.filterwarnings("ignore", message="Pydantic serializer warnings")

DEFAULT_MODEL = os.getenv("TIA_MODEL", "openai/gpt-6-luna")  # same model as the CrewAI flow


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Tools (replacements for crewai_tools ExaSearchTool and ScrapeWebsiteTool)
# --------------------------------------------------------------------------- #

class Tools:
    """Behave like the CrewAI originals: same arguments, same Exa settings, same page-text extraction."""

    SCRAPE_HEADERS = {  # identical to ScrapeWebsiteTool
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com/",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    def __init__(self, max_page_chars: int = 0):
        self.max_page_chars = max_page_chars  # 0 = no cap, as in CrewAI
        self._exa = None

    def exa_search(
        self,
        search_query: str,
        start_published_date: str | None = None,
        end_published_date: str | None = None,
        include_domains: list[str] | None = None,
    ) -> str:
        if self._exa is None:
            from exa_py import Exa

            key = os.getenv("EXA_API_KEY")
            if not key:
                raise RuntimeError("EXA_API_KEY is not set")
            self._exa = Exa(key)
        params: dict = {"type": "auto"}
        if start_published_date:
            params["start_published_date"] = start_published_date
        if end_published_date:
            params["end_published_date"] = end_published_date
        if include_domains:
            params["include_domains"] = include_domains
        # ExaSearchTool defaults: highlights on, full text and summary off
        return str(self._exa.search(search_query, contents={"highlights": True}, **params))

    def scrape_website(self, website_url: str) -> str:
        if not re.match(r"^https?://", website_url, re.I):
            raise ValueError("website_url must start with http:// or https://")
        page = requests.get(website_url, timeout=15, headers=self.SCRAPE_HEADERS)
        page.encoding = page.apparent_encoding
        parsed = BeautifulSoup(page.text, "html.parser")
        text = "The following text is scraped website content:\n\n"
        text += parsed.get_text(" ")
        text = re.sub("[ \t]+", " ", text)
        text = re.sub("\\s+\n\\s+", "\n", text)
        if self.max_page_chars and len(text) > self.max_page_chars:
            text = text[: self.max_page_chars] + f"\n\n[TRUNCATED at {self.max_page_chars} characters]"
        return text

    SCHEMAS = [
        {
            "type": "function",
            "function": {
                "name": "exa_search",
                "description": "Search the web with Exa, the fastest and most accurate web search API.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "search_query": {"type": "string", "description": "Mandatory search query you want to use to search the internet"},
                        "start_published_date": {"type": "string", "description": "Start date for the search"},
                        "end_published_date": {"type": "string", "description": "End date for the search"},
                        "include_domains": {"type": "array", "items": {"type": "string"}, "description": "List of domains to include in the search"},
                    },
                    "required": ["search_query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_website_content",
                "description": "A tool that can be used to read a website content.",
                "parameters": {
                    "type": "object",
                    "properties": {"website_url": {"type": "string", "description": "Mandatory website url to read the file"}},
                    "required": ["website_url"],
                },
            },
        },
    ]

    def call(self, name: str, raw_args: str | None) -> str:
        """Run one tool call. Errors go back to the model as text so it can fix and retry."""
        try:
            args = json.loads(raw_args or "{}")
            if name == "exa_search":
                return self.exa_search(**args)
            if name == "read_website_content":
                return self.scrape_website(**args)
            return f"ERROR: unknown tool {name!r}"
        except Exception as e:  # noqa: BLE001 - every failure is reported to the model
            return f"ERROR: {type(e).__name__}: {e}"


# --------------------------------------------------------------------------- #
# Agent runner
# --------------------------------------------------------------------------- #

def auto_max_tokens(model: str) -> int | None:
    """CrewAI sets no output cap. Use the model's own limit when LiteLLM knows it (capped at 32k)."""
    try:
        limit = litellm.get_model_info(model).get("max_output_tokens")
    except Exception:  # noqa: BLE001 - unknown model: let the provider apply its default
        return None
    return min(int(limit), 32000) if limit else None


def run_agent(name: str, model: str, user_input: str, tools: Tools | None, max_tokens: int | None, max_steps: int) -> str:
    spec = AGENTS[name]
    system = (
        f"You are {spec['role']}. {spec['backstory']}\n"
        f"Your personal goal is: {spec['goal']}"
        f"\n\nCurrent Date: {date.today().isoformat()}"
    )
    task = f"\nCurrent Task: {user_input}" + ("" if tools else "\n\nProvide your complete response:")
    messages: list = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    kwargs = {"model": model, "num_retries": 3, "timeout": 900}
    max_tokens = max_tokens or auto_max_tokens(model)
    if max_tokens:
        kwargs["max_tokens"] = max_tokens
    if tools:
        kwargs["tools"] = Tools.SCHEMAS

    for step in range(max_steps):
        if tools and step == max_steps - 1:
            # Out of tool budget: force a final answer from what has been gathered so far.
            kwargs.pop("tools")
            messages.append({"role": "user", "content": "Tool budget is used up. Give your final answer now from what you have."})
        resp = litellm.completion(messages=messages, **kwargs)
        choice = resp.choices[0]
        msg = choice.message
        if not getattr(msg, "tool_calls", None):
            if choice.finish_reason == "length":
                log(f"  [warn] {name}: output hit the token limit and was cut off; set a higher --max-tokens")
            return (msg.content or "").strip()

        # Append the provider's message object untouched: it carries Claude thinking
        # blocks and Gemini thought signatures that must be echoed back on the next turn.
        messages.append(msg)
        for tc in msg.tool_calls:
            log(f"  [{name}] {tc.function.name}({tc.function.arguments})")
            result = tools.call(tc.function.name, tc.function.arguments) if tools else "ERROR: no tools available"
            if result.startswith("ERROR"):
                log(f"    -> {result[:200]}")
            messages.append({"role": "tool", "tool_call_id": tc.id, "name": tc.function.name, "content": result})
    return ""


# --------------------------------------------------------------------------- #
# Flow
# --------------------------------------------------------------------------- #

def run_flow(threat_actor: str, models: dict[str, str], out_dir: Path, max_tokens: int | None, max_steps: int, max_page_chars: int) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    tools = Tools(max_page_chars)

    def stage(n: int, name: str, filename: str, **fmt) -> str:
        log(f"[{n}/3] {name} ({models[name]})")
        text = run_agent(
            name,
            models[name],
            AGENTS[name]["input"].format(threat_actor=threat_actor, **fmt),
            tools if AGENTS[name]["uses_tools"] else None,
            max_tokens,
            max_steps,
        )
        if not text:
            raise RuntimeError(f"{name} returned no output")
        (out_dir / filename).write_text(text + "\n", encoding="utf-8")
        return text

    reports = stage(1, "scout_reports", "01_scout_reports.md")
    observations = stage(2, "extract_observations", "02_observations.md", scout_reports=reports)
    mapping = stage(3, "map_to_attack", "03_attack_mapping.md", observations=observations)
    return mapping


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("threat_actor", nargs="?", default="Lazarus Group", help="actor to research (default: Lazarus Group)")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"LiteLLM model string for all stages (default: {DEFAULT_MODEL})")
    p.add_argument("--scout-model", help="override the model for the Scout")
    p.add_argument("--extractor-model", help="override the model for the Extractor")
    p.add_argument("--mapper-model", help="override the model for the Mapper")
    p.add_argument("--api-base", help="custom endpoint, e.g. a local OpenAI-compatible server")
    p.add_argument("--max-tokens", type=int, default=None, help="output token limit per agent (default: the model's own limit, up to 32000)")
    p.add_argument("--max-steps", type=int, default=25, help="max model turns per agent (default: 25, same as CrewAI)")
    p.add_argument("--max-page-chars", type=int, default=0, help="cap on text kept per scraped page (default: 0 = no cap, same as CrewAI)")
    p.add_argument("--out", default="output", help="output directory (default: ./output)")
    a = p.parse_args()

    if a.api_base:
        litellm.api_base = a.api_base
    models = {
        "scout_reports": a.scout_model or a.model,
        "extract_observations": a.extractor_model or a.model,
        "map_to_attack": a.mapper_model or a.model,
    }
    slug = re.sub(r"[^a-z0-9]+", "-", a.threat_actor.lower()).strip("-") or "actor"
    out_dir = Path(a.out) / slug

    try:
        result = run_flow(a.threat_actor, models, out_dir, a.max_tokens, a.max_steps, a.max_page_chars)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"Run failed: {type(e).__name__}: {e}")
    print(result)
    log(f"\nSaved to {out_dir}/")


if __name__ == "__main__":
    main()
