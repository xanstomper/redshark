<div align="center">
  
# 🎯 AI Red Teaming: The Complete Guide

</div>

<div align="center">

![AI Red Teaming](https://img.shields.io/badge/AI-Red%20Teaming-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Testing-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Updated](https://img.shields.io/badge/Updated-June%202026-orange?style=for-the-badge)

**A comprehensive guide to adversarial testing and security evaluation of AI systems, helping organizations identify vulnerabilities before attackers exploit them.**

### Trusted by practitioners at

![Microsoft](https://img.shields.io/badge/Microsoft-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Google](https://img.shields.io/badge/Google-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Meta](https://img.shields.io/badge/Meta-0467DF?style=for-the-badge&logo=meta&logoColor=white)
![OpenAI](https://img.shields.io/badge/OpenAI-412991?style=for-the-badge&logo=openai&logoColor=white)
![Anthropic](https://img.shields.io/badge/Anthropic-191919?style=for-the-badge&logo=anthropic&logoColor=white)
![NVIDIA](https://img.shields.io/badge/NVIDIA-76B900?style=for-the-badge&logo=nvidia&logoColor=white)
![IBM](https://img.shields.io/badge/IBM-052FAD?style=for-the-badge&logo=ibm&logoColor=white)
![Amazon](https://img.shields.io/badge/Amazon-FF9900?style=for-the-badge&logo=amazon&logoColor=white)
![HackerOne](https://img.shields.io/badge/HackerOne-494649?style=for-the-badge&logo=hackerone&logoColor=white)
![Cisco](https://img.shields.io/badge/Cisco-1BA0D7?style=for-the-badge&logo=cisco&logoColor=white)

<sub>Logos represent organizations where individual practitioners reference this guide; inclusion does not imply official endorsement.</sub>

[Overview](#overview) • [Frameworks](#key-frameworks-and-standards) • [Methodologies](#ai-red-teaming-methodology) • [Tools](#red-teaming-tools) • [Case Studies](#real-world-case-studies) • [Resources](#resources-and-references)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [What is AI Red Teaming?](#what-is-ai-red-teaming)
- [Why AI Red Teaming Matters](#why-ai-red-teaming-matters)
- [Key Frameworks and Standards](#key-frameworks-and-standards)
  - [NIST AI Risk Management Framework](#nist-ai-risk-management-framework)
  - [OWASP GenAI Red Teaming Guide](#owasp-genai-red-teaming-guide)
  - [OWASP Top 10 for Agentic Applications (2026)](#owasp-top-10-for-agentic-applications-2026)
  - [MITRE ATLAS](#mitre-atlas)
  - [CSA Agentic AI Red Teaming](#csa-agentic-ai-red-teaming)
  - [Microsoft Agentic Failure-Mode Taxonomy v2.0](#microsoft-agentic-failure-mode-taxonomy-v20)
- [AI Red Teaming Methodology](#ai-red-teaming-methodology)
- [Threat Landscape](#threat-landscape)
- [Attack Vectors and Techniques](#attack-vectors-and-techniques)
- [MCP & Tool-Protocol Security](#mcp--tool-protocol-security)
- [Computer-Use & Browser Agent Attacks](#computer-use--browser-agent-attacks)
- [RAG Attack Taxonomy](#rag-attack-taxonomy)
- [Voice, Audio & Multimodal Attacks](#voice-audio--multimodal-attacks)
- [Fine-Tuning & Model Supply-Chain Security](#fine-tuning--model-supply-chain-security)
- [AI-on-AI Red Teaming](#ai-on-ai-red-teaming)
- [Red Teaming Tools](#red-teaming-tools)
- [Real-World Case Studies](#real-world-case-studies)
- [Building Your Red Team](#building-your-red-team)
- [Best Practices](#best-practices)
- [Implementation Quickstart (30/60/90)](#implementation-quickstart-306090)
- [Evaluation Harness (Reference Implementation)](#evaluation-harness-reference-implementation)
- [Agentic AI Attack Trees + Controls Mapping](#agentic-ai-attack-trees--controls-mapping)
- [AI Harm Severity and Triage Model](#ai-harm-severity-and-triage-model)
- [AI Incident Response](#ai-incident-response)
- [Secure SDLC Integration Artifacts](#secure-sdlc-integration-artifacts)
- [Regulatory Compliance](#regulatory-compliance)
- [Resources and References](#resources-and-references)

---

<a id="overview"></a>

## 🎯 Overview

As artificial intelligence systems become increasingly integrated into critical business operations, healthcare, finance, and decision-making processes, ensuring their security and reliability has never been more important. AI red teaming has emerged as a fundamental security practice that helps organizations identify vulnerabilities before they can be exploited in real-world scenarios.

This comprehensive guide is designed for:

- 🔐 **Security Teams** implementing AI security testing programs
- 🛡️ **AI/ML Engineers** building secure AI systems
- 👨‍💼 **Risk Managers** assessing AI-related risks
- 🏢 **Organizations** deploying AI in production
- 🎓 **Researchers** studying AI security and safety
- 📊 **Compliance Officers** ensuring regulatory adherence

### Why This Guide?

- ✅ **Evidence-Based**: Grounded in real-world experience from Microsoft's 100+ AI product red teams
- ✅ **Framework-Aligned**: Incorporates NIST AI RMF, OWASP, MITRE ATLAS, and CSA guidelines
- ✅ **Practical Focus**: Actionable methodologies and tools you can implement today
- ✅ **Continuously Updated**: Reflects latest 2024-2026 research and industry practices
- ✅ **Comprehensive Coverage**: From basic concepts to advanced attack techniques

---

<a id="what-is-ai-red-teaming"></a>

## 🤖 What is AI Red Teaming?

**AI Red Teaming** is a structured, proactive security practice where expert teams simulate adversarial attacks on AI systems to uncover vulnerabilities and improve their security and resilience. Unlike traditional security testing that focuses on known attack vectors, AI red teaming embraces creative, open-ended exploration to discover novel failure modes and risks.

### Core Principles

AI red teaming adapts military and cybersecurity red team concepts to the unique challenges posed by AI systems:

| Traditional Cybersecurity | AI Red Teaming |
|---------------------------|----------------|
| Tests against known vulnerabilities | Discovers novel, emergent risks |
| Binary pass/fail outcomes | Probabilistic behaviors and edge cases |
| Static attack surface | Dynamic, context-dependent vulnerabilities |
| Code-level exploits | Natural language attacks via prompts |
| Deterministic systems | Non-deterministic AI behaviors |

### Key Definitions

- **Red Team**: Group simulating adversarial attacks to test system security
- **Blue Team**: Defensive team working to protect and secure systems
- **Purple Team**: Collaborative approach combining red and blue team insights
- **Attack Surface**: All potential points where an AI system can be exploited
- **Jailbreaking**: Bypassing AI safety guardrails to elicit prohibited outputs
- **Prompt Injection**: Manipulating AI behavior through crafted input prompts
- **Model Extraction**: Stealing proprietary AI models through API queries
- **Data Poisoning**: Corrupting training data to compromise model behavior

---

<a id="why-ai-red-teaming-matters"></a>

## 🚨 Why AI Red Teaming Matters

### The Urgency of AI Security

Recent security incidents demonstrate that AI systems face unique challenges traditional cybersecurity cannot address:

**2025–2026 Security Incidents:**
- **January 2026**: The OpenClaw agent framework shipped with 512 vulnerabilities, including a one-click remote code execution flaw (CVE-2026-25253); within a week 1,800+ instances were exposed leaking API keys, and 336 malicious plugins (credential stealers disguised as trading bots) reached its skills marketplace.
- **September 2025**: Anthropic detected and disrupted the first documented large-scale cyberattack predominantly executed by an AI agent — a state-sponsored operation in which Claude Code autonomously handled an estimated 80–90% of tactical execution across ~30 global targets.
- **August 2025**: GitHub Copilot remote code execution (CVE-2025-53773, CVSS 9.6) via prompt injection that wrote to the agent's configuration files.
- **2025**: Prompt-injection research demonstrated against AI-enabled browsers (Perplexity's Comet, Gemini for Chrome) and coding assistants (GitLab Duo, Copilot Chat).
- **2023–2024 (historical)**: Samsung's ChatGPT data leak, the March 2025 ChatGPT exploit, and the Microsoft health-chatbot data exposure remain instructive early examples (see [Real-World Case Studies](#real-world-case-studies)).

> **By the numbers (vendor-/researcher-reported, 2025).** Estimated global losses from AI prompt-injection attacks reached ~$2.3B, a reported +340% year over year; ~88% of organizations deploying AI agents reported confirmed or suspected security incidents; current detection methods are reported to catch only ~23% of sophisticated prompt-injection attempts. *Treat these as directional industry figures, not audited statistics — sources are listed in [Resources and References](#resources-and-references).*

### The Stakes Are Higher

In 2026, AI and LLMs are no longer limited to chatbots and virtual assistants for customer support. Autonomous, tool-using **agents** now act on behalf of users — booking, buying, coding, and operating infrastructure — which converts what used to be "bad text output" into real-world actions: data exfiltration, lateral movement, and unauthorized transactions. Their use increasingly expands into high-stakes applications such as healthcare diagnostics, financial decision-making, and critical infrastructure systems.

### Regulatory Drivers

Article 15 of the European Union AI Act obliges operators of high-risk AI systems to demonstrate accuracy, robustness and cybersecurity. The US Executive Order on AI defines AI red teaming as "a structured testing effort to find flaws and vulnerabilities in an AI system using adversarial methods to identify harmful or discriminatory outputs, unforeseen behaviors, or misuse risks."

### Business Impact

- **Reputation Risk**: AI failures can cause immediate brand damage
- **Financial Loss**: Data breaches and service disruptions cost millions
- **Legal Liability**: Non-compliance with AI regulations brings penalties
- **Competitive Advantage**: Secure AI builds customer trust
- **Innovation Enablement**: Understanding risks allows safer experimentation

---

<a id="key-frameworks-and-standards"></a>

## 📚 Key Frameworks and Standards

### NIST AI Risk Management Framework

The NIST AI Risk Management Framework (AI RMF) emphasizes continuous testing and evaluation throughout the AI system's lifecycle, providing a structured approach for organizations to implement comprehensive AI security testing programs.

**Four Core Functions:**

#### 1. **GOVERN**
Establish AI governance structures and risk management culture
- Develop AI risk policies and procedures
- Assign roles and responsibilities
- Integrate AI risks into enterprise risk management

#### 2. **MAP**
Identify and categorize AI risks in context
- Understand AI system capabilities and limitations
- Document intended use cases and deployment contexts
- Identify potential risks and stakeholders

#### 3. **MEASURE**
Assess, analyze, and track identified AI risks
- NIST recommends red teaming as an approach consisting of adversarial testing of AI systems under stress conditions to seek out AI system failure modes or vulnerabilities
- Evaluate trustworthiness characteristics
- Track metrics for fairness, bias, and robustness
- Use tools like **Dioptra** (NIST's security testbed) for model testing

#### 4. **MANAGE**
Prioritize and respond to identified risks
- Implement risk mitigation strategies
- Monitor AI systems in production
- Maintain incident response capabilities

**Key NIST Resources:**
- **AI RMF (NIST AI 100-1)**: Core framework
