"""Offline smoke test: fakes the model and the two tools, checks the wiring end to end."""
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS

import tia

calls = []


def fake_completion(messages, **kw):
    calls.append((messages, kw))
    system = messages[0]["content"]
    last = messages[-1]
    last_role = last["role"] if isinstance(last, dict) else "assistant"
    if "Scout" in system:
        n_tool = sum(1 for m in messages if isinstance(m, dict) and m["role"] == "tool")
        if n_tool == 0:
            tc = [NS(id="c1", function=NS(name="exa_search", arguments='{"search_query": "Lazarus Group report", "include_domains": ["cisa.gov"]}')),
                  NS(id="c2", function=NS(name="read_website_content", arguments=""))]  # bad args on purpose
            return NS(choices=[NS(finish_reason="tool_calls", message=NS(content=None, tool_calls=tc))])
        assert last_role == "tool" and messages[-1]["content"].startswith("ERROR"), messages[-1]
        assert "example.com/r1" in messages[-2]["content"]
        return NS(choices=[NS(finish_reason="stop", message=NS(content="REPORT-BLOCK {braces}\n1 reports", tool_calls=None))])
    assert "tools" not in kw
    if "Extractor" in system:
        assert "REPORT-BLOCK {braces}" in last["content"] and "Lazarus Group" in last["content"]
        return NS(choices=[NS(finish_reason="stop", message=NS(content="1. behavior: LSASS dump", tool_calls=None))])
    assert "Mapping Specialist" in system and "1. behavior: LSASS dump" in last["content"]
    return NS(choices=[NS(finish_reason="stop", message=NS(content="| 1 | Credential Access | T1003.001 |", tool_calls=None))])


tia.litellm.completion = fake_completion
tia.Tools.exa_search = lambda self, search_query, **kw: json.dumps([{"url": "https://example.com/r1"}])

with tempfile.TemporaryDirectory() as d:
    models = {k: "fake/model" for k in tia.AGENTS}
    out = tia.run_flow("Lazarus Group", models, Path(d), None, 10, 0)
    assert "T1003.001" in out
    assert sorted(p.name for p in Path(d).iterdir()) == ["01_scout_reports.md", "02_observations.md", "03_attack_mapping.md"]
    assert len(calls) == 4, len(calls)
    assert "\n\nCurrent Date: 20" in calls[0][0][0]["content"]
    assert calls[0][0][1]["content"].startswith("\nCurrent Task: Threat actor: Lazarus Group")
    assert calls[2][0][1]["content"].endswith("Provide your complete response:")
    assert "max_tokens" not in calls[0][1]  # unknown model: provider default

# tool-budget cutoff: a model that never stops calling tools must still be forced to answer
def looping(messages, **kw):
    if "tools" in kw:
        tc = [NS(id="x", function=NS(name="exa_search", arguments='{"search_query": "q"}'))]
        return NS(choices=[NS(finish_reason="tool_calls", message=NS(content=None, tool_calls=tc))])
    return NS(choices=[NS(finish_reason="stop", message=NS(content="forced answer", tool_calls=None))])

tia.litellm.completion = looping
assert tia.run_agent("scout_reports", "fake", "x", tia.Tools(), None, 3) == "forced answer"

# real scraper guards
t = tia.Tools(100)
assert t.call("read_website_content", '{"website_url": "file:///etc/passwd"}').startswith("ERROR")
assert t.call("nope", "{}").startswith("ERROR")
print("offline test passed")

# scraper output must match CrewAI's ScrapeWebsiteTool text extraction byte for byte
import re
from bs4 import BeautifulSoup
html = "<html><head><title>T</title></head><body><header>H1  x</header><p>IOC\t 1.2.3.4</p>\n\n  <footer>Appendix: hash abc</footer></body></html>"
class R: text = html; apparent_encoding = "utf-8"; encoding = None
tia.requests.get = lambda *a, **k: R()
ref = "The following text is scraped website content:\n\n" + BeautifulSoup(html, "html.parser").get_text(" ")
ref = re.sub("\\s+\n\\s+", "\n", re.sub("[ \t]+", " ", ref))
got = tia.Tools().scrape_website("https://x.test/")
assert got == ref and "Appendix: hash abc" in got and "H1 x" in got, (got, ref)
assert tia.auto_max_tokens("openai/gpt-4o") == 16384 and tia.auto_max_tokens("nope/zzz") is None
print("parity checks passed")
