# ZTNA Token Gate Simulator

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)
[![Zero-Trust](https://img.shields.io/badge/Zero--Trust-Architecture-red)](https://www.nist.gov/publications/zero-trust-architecture)

A production‑ready, zero‑dependency Python 3 simulator that models a **Zero‑Trust Network Access (ZTNA)** token gate. It evaluates every access request against a dynamic, context‑aware policy engine and grants adaptive session tokens only when all explicit trust conditions are satisfied – otherwise, it instantly drops the connection and raises a security alert.

---

## 🧠 High‑Level Technical Overview

The engine implements a **continuous verification** loop that ingests a live stream of login attempts. Each request carries a user identity, device fingerprint, source IP, and timestamp. The policy engine correlates these attributes against a centralised identity context matrix (user roles, risk scores, MFA status) and a device posture database (OS, patch compliance). By fusing this telemetry with geographic IP fencing and temporal business‑hour constraints, the gate applies a **strict default‑deny** stance – only a fully compliant request receives a time‑bound token.
