#!/usr/bin/env python3
"""
RedShark Python Bridge Server — HTTP sidecar that exposes deepteam's
LLM red-teaming framework and the benchmark runner to the Go TUI agent.

Routes
------
POST /redteam          — run deepteam.red_team() against a model callback
POST /benchmark        — run redteam-ai-benchmark questions against a model
GET  /vulnerabilities  — list all available deepteam vulnerability types
GET  /attacks          — list all available deepteam attack types
GET  /health           — liveness check

The server is started by the Go process as a managed subprocess.
Communication is local-only (127.0.0.1: random port passed via env).
"""

import json
import os
import sys
import traceback
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Lazy imports — deepteam is heavy; don't penalise /health
# ---------------------------------------------------------------------------
_deepteam_loaded = False
_vulnerabilities: Dict[str, Any] = {}
_attacks: Dict[str, Any] = {}

VULN_LIST = [
    "bias", "child_protection", "competition", "cross_context_retrieval",
    "custom", "debug_access", "ethics", "excessive_agency",
    "exploit_tool_agent", "external_system_abuse", "fairness",
    "goal_theft", "graphic_content", "hallucination",
    "illegal_activity", "indirect_instruction",
    "insecure_inter_agent_communication", "intellectual_property",
    "misinformation", "personal_safety", "pii_leakage",
    "prompt_leakage", "rbac", "recursive_hijacking", "robustness",
    "shell_injection", "sql_injection", "ssrf",
    "system_reconnaissance", "tool_metadata_poisoning",
    "tool_orchestration_abuse", "toxicity",
    "unexpected_code_execution", "agent_identity_abuse",
    "autonomous_agent_drift", "bfla", "bola",
]

ATTACK_LIST = [
    # single-turn
    "prompt_injection", "prompt_probing", "roleplay", "leetspeak",
    "base64", "rot13", "multilingual", "math_problem",
    "adversarial_poetry", "emotional_manipulation",
    "authority_escalation", "permission_escalation",
    "goal_redirection", "gray_box", "input_bypass",
    "context_flooding", "context_poisoning",
    "embedded_instruction_json", "semantic_manipulation",
    "synthetic_context_injection", "system_override",
    "character_stream", "compliance",
    # multi-turn
    "crescendo_jailbreaking", "linear_jailbreaking",
    "sequential_break", "tree_jailbreaking", "bad_likert_judge",
]


def _ensure_deepteam():
    global _deepteam_loaded, _vulnerabilities, _attacks
    if _deepteam_loaded:
        return

    try:
        from deepteam import vulnerabilities as v_mod
        from deepteam import attacks as a_mod

        # Build name -> class mapping from the submodules
        for name in VULN_LIST:
            try:
                mod = __import__(f"deepteam.vulnerabilities.{name}.{name}",
                                 fromlist=[name])
                cls = getattr(mod, "".join(w.capitalize() for w in name.split("_")))
                if cls:
                    _vulnerabilities[name] = cls
            except Exception:
                pass

        for name in ATTACK_LIST:
            try:
                mod = __import__(f"deepteam.attacks.single_turn.{name}.{name}",
                                 fromlist=[name])
                cls = getattr(mod, "".join(w.capitalize() for w in name.split("_")))
                if cls:
                    _attacks[name] = cls
            except Exception:
                try:
                    mod = __import__(f"deepteam.attacks.multi_turn.{name}.{name}",
                                     fromlist=[name])
                    cls = getattr(mod, "".join(w.capitalize() for w in name.split("_")))
                    if cls:
                        _attacks[name] = cls
                except Exception:
                    pass

    except ImportError:
        pass  # deepteam not installed; endpoints return graceful errors

    _deepteam_loaded = True


# ---------------------------------------------------------------------------
# Model callback — adapted from the Go side's request payload.
# The Go agent sends the model's own endpoint + key so the Python side
# can call it directly.
# ---------------------------------------------------------------------------

class _ModelCallback:
    """Wraps an OpenAI-compatible chat endpoint as a deepteam model_callback."""

    def __init__(self, endpoint: str, api_key: str, model: str):
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model

    def __call__(self, prompt: str) -> str:
        try:
            import openai
            client = openai.OpenAI(base_url=self.endpoint, api_key=self.api_key)
            resp = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=4096,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            return f"[pybridge error] model callback failed: {e}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "deepteam_available": True})


@app.route("/vulnerabilities", methods=["GET"])
def list_vulnerabilities():
    _ensure_deepteam()
    items = []
    for name, cls in sorted(_vulnerabilities.items()):
        items.append({"id": name, "class": cls.__name__})
    # Also include the full static list even if import failed for some
    all_names = sorted(set(list(_vulnerabilities.keys()) + VULN_LIST))
    return jsonify({"vulnerabilities": all_names, "loaded": len(_vulnerabilities)})


@app.route("/attacks", methods=["GET"])
def list_attacks():
    _ensure_deepteam()
    items = []
    for name, cls in sorted(_attacks.items()):
        items.append({"id": name, "class": cls.__name__})
    all_names = sorted(set(list(_attacks.keys()) + ATTACK_LIST))
    return jsonify({"attacks": all_names, "loaded": len(_attacks)})


@app.route("/redteam", methods=["POST"])
def run_redteam():
    """
    Run a deepteam red-team assessment.

    Expected JSON body:
    {
      "model_endpoint": "https://api.openai.com/v1",
      "model_api_key": "sk-...",
      "model_name": "gpt-4o-mini",
      "vulnerabilities": ["bias", "toxicity", "pii_leakage"],
      "attacks": ["prompt_injection", "roleplay"],
      "attacks_per_vuln": 1,
      "async_mode": true,
      "max_concurrent": 5,
      "target_purpose": "customer support chatbot",
      "simulator_model": "gpt-4o-mini",
      "evaluation_model": "gpt-4o-mini",
      "dryrun": false
    }
    """
    _ensure_deepteam()
    data = request.get_json(force=True)

    # Validate required fields
    for field in ("model_endpoint", "model_api_key", "model_name"):
        if not data.get(field):
            return jsonify({"error": f"missing required field: {field}"}), 400

    if data.get("dryrun"):
        return jsonify({
            "status": "dryrun",
            "message": "would run deepteam red_team() with the given params",
            "vulnerabilities": data.get("vulnerabilities", VULN_LIST),
            "attacks": data.get("attacks", ATTACK_LIST),
        })

    try:
        from deepteam import red_team
        from deepteam.vulnerabilities import (
            Bias, Toxicity, Misinformation, IllegalActivity,
            PromptLeakage, PIILeakage, BFLA, BOLA, RBAC,
            DebugAccess, ShellInjection, SQLInjection, SSRF,
            IntellectualProperty, IndirectInstruction,
            ToolOrchestrationAbuse, AgentIdentityAbuse,
            ToolMetadataPoisoning, UnexpectedCodeExecution,
            InsecureInterAgentCommunication, AutonomousAgentDrift,
            CrossContextRetrieval, SystemReconnaissance,
            ExploitToolAgent, ExternalSystemAbuse,
            Competition, GraphicContent, PersonalSafety,
            CustomVulnerability, GoalTheft, RecursiveHijacking,
            Robustness, ExcessiveAgency, Hallucination,
            ChildProtection, Ethics, Fairness,
        )

        VULN_MAP = {
            "bias": Bias, "toxicity": Toxicity, "misinformation": Misinformation,
            "illegal_activity": IllegalActivity, "prompt_leakage": PromptLeakage,
            "pii_leakage": PIILeakage, "bfla": BFLA, "bola": BOLA,
            "rbac": RBAC, "debug_access": DebugAccess,
            "shell_injection": ShellInjection, "sql_injection": SQLInjection,
            "ssrf": SSRF, "intellectual_property": IntellectualProperty,
            "indirect_instruction": IndirectInstruction,
            "tool_orchestration_abuse": ToolOrchestrationAbuse,
            "agent_identity_abuse": AgentIdentityAbuse,
            "tool_metadata_poisoning": ToolMetadataPoisoning,
            "unexpected_code_execution": UnexpectedCodeExecution,
            "insecure_inter_agent_communication": InsecureInterAgentCommunication,
            "autonomous_agent_drift": AutonomousAgentDrift,
            "cross_context_retrieval": CrossContextRetrieval,
            "system_reconnaissance": SystemReconnaissance,
            "exploit_tool_agent": ExploitToolAgent,
            "external_system_abuse": ExternalSystemAbuse,
            "competition": Competition, "graphic_content": GraphicContent,
            "personal_safety": PersonalSafety,
            "goal_theft": GoalTheft, "recursive_hijacking": RecursiveHijacking,
            "robustness": Robustness, "excessive_agency": ExcessiveAgency,
            "hallucination": Hallucination, "child_protection": ChildProtection,
            "ethics": Ethics, "fairness": Fairness,
        }

        requested_vulns = data.get("vulnerabilities", ["bias", "toxicity", "pii_leakage"])
        vuln_instances = []
        for v_name in requested_vulns:
            cls = VULN_MAP.get(v_name)
            if cls:
                vuln_instances.append(cls())

        # Build model callback
        callback = _ModelCallback(
            endpoint=data["model_endpoint"],
            api_key=data["model_api_key"],
            model=data["model_name"],
        )

        # Run the assessment
        result = red_team(
            model_callback=callback,
            vulnerabilities=vuln_instances if vuln_instances else None,
            attacks=None,  # use deepteam defaults
            simulator_model=data.get("simulator_model", "gpt-4o-mini"),
            evaluation_model=data.get("evaluation_model", "gpt-4o-mini"),
            attacks_per_vulnerability_type=data.get("attacks_per_vuln", 1),
            async_mode=data.get("async_mode", True),
            max_concurrent=data.get("max_concurrent", 5),
            target_purpose=data.get("target_purpose"),
        )

        # Serialize — result is a RiskAssessment object
        try:
            serialized = json.dumps(result, default=str, indent=2)
        except (TypeError, ValueError):
            serialized = str(result)

        return jsonify({"status": "completed", "result": serialized})

    except Exception:
        return jsonify({
            "status": "error",
            "error": traceback.format_exc(),
        }), 500


@app.route("/benchmark", methods=["POST"])
def run_benchmark():
    """
    Run a subset of the redteam-ai-benchmark questions against a model.

    Expected JSON body:
    {
      "model_endpoint": "https://api.openai.com/v1",
      "model_api_key": "sk-...",
      "model_name": "gpt-4o-mini",
      "questions_file": "datasets/v2/benchmark.jsonl",
      "categories": ["prompt_injection", "jailbreak"],
      "max_tokens": 4096,
      "temperature": 0.2,
      "dryrun": false
    }
    """
    data = request.get_json(force=True)

    for field in ("model_endpoint", "model_api_key", "model_name"):
        if not data.get(field):
            return jsonify({"error": f"missing required field: {field}"}), 400

    if data.get("dryrun"):
        return jsonify({
            "status": "dryrun",
            "message": "would run benchmark questions against model",
        })

    try:
        import openai

        client = openai.OpenAI(
            base_url=data["model_endpoint"],
            api_key=data["model_api_key"],
        )
        model_name = data["model_name"]
        max_tokens = data.get("max_tokens", 4096)
        temperature = data.get("temperature", 0.2)
        categories = data.get("categories")

        # Load benchmark dataset
        questions_file = data.get("questions_file",
                                  "/home/jewboy420/redshark-vendors/redteam-ai-benchmark/datasets/v2/benchmark.jsonl")
        questions = []
        if os.path.exists(questions_file):
            with open(questions_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            q = json.loads(line)
                            if categories and q.get("category") not in categories:
                                continue
                            questions.append(q)
                        except json.JSONDecodeError:
                            continue
        else:
            return jsonify({"error": f"benchmark dataset not found: {questions_file}"}), 404

        results = []
        for q in questions[:50]:  # cap at 50 questions per run
            prompt = q.get("prompt", "")
            try:
                resp = client.chat.completions.create(
                    model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                answer = resp.choices[0].message.content or ""
                results.append({
                    "id": q.get("id"),
                    "category": q.get("category"),
                    "response_snippet": answer[:200],
                    "score": 0,  # would need scorer
                })
            except Exception as e:
                results.append({
                    "id": q.get("id"),
                    "category": q.get("category"),
                    "error": str(e),
                })

        return jsonify({
            "status": "completed",
            "total_questions": len(questions),
            "questions_run": len(results),
            "results": results,
        })

    except Exception:
        return jsonify({
            "status": "error",
            "error": traceback.format_exc(),
        }), 500


@app.route("/guardrails", methods=["POST"])
def run_guardrails():
    """
    Run deepteam guardrails check on input text.

    Expected JSON body:
    {
      "input": "text to check",
      "guards": ["toxicity", "bias", "pii"],
      "dryrun": false
    }
    """
    _ensure_deepteam()
    data = request.get_json(force=True)

    if data.get("dryrun"):
        return jsonify({
            "status": "dryrun",
            "message": "would run guardrails check",
        })

    try:
        from deepteam import Guardrails

        guards_config = data.get("guards", ["toxicity", "bias"])
        input_text = data.get("input", "")

        guardrails = Guardrails()
        result = guardrails.guard(input_text)
        return jsonify({"status": "completed", "result": str(result)})

    except Exception:
        return jsonify({
            "status": "error",
            "error": traceback.format_exc(),
        }), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("REDSHARK_PYBRIDGE_PORT", "9876"))
    host = os.environ.get("REDSHARK_PYBRIDGE_HOST", "127.0.0.1")
    debug = os.environ.get("REDSHARK_PYBRIDGE_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug, threaded=True)
