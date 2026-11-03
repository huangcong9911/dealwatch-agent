"""Tiny client for Vultr Serverless Inference (OpenAI-compatible API)."""
import json
import os
import re

import httpx

BASE_URL = os.environ.get("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
API_KEY = os.environ.get("VULTR_INFERENCE_API_KEY", "")
MODEL = os.environ.get("DEALWATCH_MODEL", "qwen3.8-flash-next")
VISION_MODEL = os.environ.get("DEALWATCH_VISION_MODEL", MODEL)


class LLMError(RuntimeError):
    pass


def chat(messages, model=None, max_tokens=1500, temperature=0.1, timeout=90):
    if not API_KEY:
        raise LLMError("VULTR_INFERENCE_API_KEY is not set")
    r = httpx.post(
        BASE_URL.rstrip("/") + "/chat/completions",
        headers={"Authorization": "Bearer " + API_KEY},
        json={"model": model or MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": temperature},
        timeout=timeout,
    )
    if r.status_code >= 400:
        raise LLMError("inference HTTP %s: %s" % (r.status_code, r.text[:300]))
    data = r.json()
    msg = data["choices"][0]["message"]
    content = msg.get("content") or ""
    if isinstance(content, list):
        content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
    return content, data.get("usage", {}), data.get("model", model or MODEL)


def parse_json(text):
    """Pull the first JSON object out of a model reply (handles ```json fences and <think> blocks)."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if m:
        text = m.group(1)
    start = text.find("{")
    if start < 0:
        raise LLMError("no JSON in model reply")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise LLMError("unterminated JSON in model reply")


def chat_json(messages, **kw):
    content, usage, model = chat(messages, **kw)
    return parse_json(content), usage, model
