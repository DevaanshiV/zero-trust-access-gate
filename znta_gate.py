#!/usr/bin/env python3
"""
ZTNA Token Gate Simulator - Zero-Trust Network Access Utility
IIT Kanpur B.Cyber Proof-of-Work Portfolio

This script simulates a Zero-Trust Network Access (ZTNA) token gate that evaluates
every access request in real‑time against a dynamic context‑aware policy engine.
It uses ONLY Python built‑in libraries (time, random, json, argparse, sys, etc.)
and outputs a live terminal monitoring stream with coloured status indicators.

Architecture:
- Identity Context Matrix: stores user profiles (roles, MFA status, risk scores),
  device compliance postures (patch level, OS), and geographic IP restrictions.
- Explicit Authorization Policies: every request must satisfy:
  1. User risk score <= threshold (default 70)
  2. Device is compliant (patch level >= minimum, OS supported)
  3. Source IP not in blocked geographic ranges
  4. Time of day within business hours (optional)
  5. MFA requirement if risk score > 50
- Adaptive Token Grant: upon successful validation, a simulated token is issued;
  otherwise the connection is dropped with a security breach alert.
- Continuous traffic stream: auto‑generates random login attempts with realistic
  attributes; accepts command‑line parameters for iterations, interval, and seed.

Output:
- Live terminal feed with colour‑coded [ACCESS GRANTED] (green) or [ACCESS DENIED] (red)
  messages showing session identifiers and telemetry.
- Final ASCII summary table with key metrics.

Run example:
    python ztna_gate.py --iterations 50 --interval 0.5 --seed 42
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

# ---------- ANSI Colour Codes for Terminal Output ----------
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[96m"
COLOR_MAGENTA = "\033[95m"

# ---------- Global Policy Configuration ----------
MAX_RISK_SCORE = 70               # above this → automatic deny
MIN_PATCH_LEVEL = 3               # device patch level must be >= this
BUSINESS_HOURS_START = 8          # 8 AM
BUSINESS_HOURS_END = 20           # 8 PM
MFA_RISK_THRESHOLD = 50           # if risk > 50, MFA is mandatory
ALLOWED_GEO_CODES = {"US", "IN", "EU"}   # allowed country codes

# ---------- Data Generators ----------
def generate_user_profiles(count: int = 10) -> Dict[str, Dict[str, Any]]:
    """Create a set of mock user profiles with identity attributes."""
    users = {}
    roles = ["employee", "manager", "admin", "contractor", "guest"]
    for i in range(1, count + 1):
        user_id = f"user{i:03d}"
        users[user_id] = {
            "role": random.choice(roles),
            "mfa_enabled": random.choice([True, False]),
            "risk_score": random.randint(0, 100),   # 0=low, 100=high
            "trust_score": random.randint(30, 100), # not directly used but for context
        }
    return users

def generate_devices(users: Dict[str, Dict[str, Any]], count: int = 15) -> Dict[str, Dict[str, Any]]:
    """Create device records linked to users, with patch compliance."""
    devices = {}
    os_choices = ["Windows 10", "Windows 11", "macOS 13", "macOS 14", "Linux Ubuntu 22.04", "Linux Ubuntu 24.04"]
    for i in range(1, count + 1):
        device_id = f"dev{i:03d}"
        user_id = random.choice(list(users.keys()))
        patch_level = random.randint(0, 5)   # 0 = unpatched, 5 = latest
        compliant = patch_level >= MIN_PATCH_LEVEL
        devices[device_id] = {
            "user_id": user_id,
            "os": random.choice(os_choices),
            "patch_level": patch_level,
            "compliant": compliant,
        }
    return devices

def generate_ip_ranges() -> Dict[str, Dict[str, Any]]:
    """Mock geographic IP restriction ranges mapping to country codes."""
    # Simulate IP ranges by country code (simplified)
    # In reality, we'd map CIDR blocks, but here we use country codes for demonstration.
    ranges = {
        "10.0.0.0/8": {"country": "US", "allowed": True},
        "192.168.0.0/16": {"country": "IN", "allowed": True},
        "172.16.0.0/12": {"country": "EU", "allowed": True},
        "203.0.113.0/24": {"country": "RU", "allowed": False},   # blocked
        "198.51.100.0/24": {"country": "CN", "allowed": False},  # blocked
    }
    return ranges

def generate_ip(country_code: Optional[str] = None) -> str:
    """Generate a random private/public IP that maps to a country."""
    # For simplicity, we'll map to known ranges based on country.
    if country_code == "US":
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    elif country_code == "IN":
        return f"192.168.{random.randint(0,255)}.{random.randint(0,255)}"
    elif country_code == "EU":
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(0,255)}"
    elif country_code == "RU":
        return f"203.0.113.{random.randint(0,255)}"
    elif country_code == "CN":
        return f"198.51.100.{random.randint(0,255)}"
    else:
        # random other
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

def get_country_from_ip(ip: str, ip_ranges: Dict[str, Dict[str, Any]]) -> Tuple[str, bool]:
    """Determine country and allowed status from IP using mock ranges."""
    # In a real system, we'd do CIDR matching. Here we just simulate based on prefix.
    for cidr, info in ip_ranges.items():
        prefix = cidr.split('/')[0].rsplit('.', 1)[0]  # e.g., "10.0.0"
        if ip.startswith(prefix):
            return info["country"], info["allowed"]
    # If no match, default allowed? For demo, we'll treat as unknown but allowed by default.
    return "UNKNOWN", True

# ---------- Policy Evaluation Engine ----------
def evaluate_request(
    user: Dict[str, Any],
    device: Dict[str, Any],
    ip: str,
    timestamp: datetime,
    ip_ranges: Dict[str, Dict[str, Any]]
) -> Tuple[bool, str]:
    """
    Zero‑Trust policy evaluation.
    Returns (granted, reason) where reason explains the decision.
    """
    # 1. User risk check
    if user["risk_score"] > MAX_RISK_SCORE:
        return False, f"User risk score {user['risk_score']} exceeds threshold {MAX_RISK_SCORE}"

    # 2. Device compliance
    if not device["compliant"]:
        patch = device["patch_level"]
        return False, f"Device not compliant (patch level {patch} < {MIN_PATCH_LEVEL})"

    # 3. Geographic IP restriction
    country, allowed = get_country_from_ip(ip, ip_ranges)
    if not allowed:
        return False, f"IP from blocked country {country}"

    # 4. Time of day (business hours)
    hour = timestamp.hour
    if not (BUSINESS_HOURS_START <= hour <= BUSINESS_HOURS_END):
        return False, f"Access outside business hours (current hour {hour})"

    # 5. MFA mandatory if risk > threshold
    if user["risk_score"] > MFA_RISK_THRESHOLD and not user["mfa_enabled"]:
        return False, f"MFA required but not enabled (risk {user['risk_score']} > {MFA_RISK_THRESHOLD})"

    # All checks passed
    return True, "All policies satisfied"

# ---------- Live Monitoring Output ----------
def print_granted(session_id: str, user_id: str, device_id: str, ip: str, timestamp: str):
    """Print green access granted message."""
    print(f"{COLOR_GREEN}{COLOR_BOLD}[ACCESS GRANTED - TOKEN ISSUED]{COLOR_RESET} "
          f"Session: {session_id} | User: {user_id} | Device: {device_id} | "
          f"IP: {ip} | Time: {timestamp}")

def print_denied(session_id: str, user_id: str, device_id: str, ip: str, timestamp: str, reason: str):
    """Print red access denied message."""
    print(f"{COLOR_RED}{COLOR_BOLD}[ACCESS DENIED - Context-Aware Security Breach Intercepted]{COLOR_RESET} "
          f"Session: {session_id} | User: {user_id} | Device: {device_id} | "
          f"IP: {ip} | Time: {timestamp} | Reason: {reason}")

# ---------- Summary Statistics ----------
def print_summary(stats: Dict[str, Any]):
    """Display final ASCII table with key metrics."""
    total = stats["total"]
    granted = stats["granted"]
    denied = stats["denied"]
    grant_rate = (granted / total * 100) if total else 0

    print("\n" + "=" * 80)
    print(f"{COLOR_BOLD}{COLOR_CYAN}ZTNA TOKEN GATE - FINAL CONTEXT VERIFICATION METRICS{COLOR_RESET}")
    print("=" * 80)
    print(f"{'Total Access Requests:':<30} {total}")
    print(f"{'Granted:':<30} {COLOR_GREEN}{granted}{COLOR_RESET}")
    print(f"{'Denied:':<30} {COLOR_RED}{denied}{COLOR_RESET}")
    print(f"{'Grant Rate:':<30} {grant_rate:.2f}%")
    print(f"{'Top Denial Reasons:':<30}")
    reason_counts = stats["reason_counts"]
    # Sort by count descending
    sorted_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)
    for reason, count in sorted_reasons[:5]:
        print(f"  - {reason}: {count}")
    print("=" * 80)

# ---------- Main Simulation Loop ----------
def run_simulation(iterations: int, interval: float, seed: Optional[int] = None):
    """Generate continuous login traffic and evaluate each request."""
    if seed is not None:
        random.seed(seed)

    # Initialize context matrix
    users = generate_user_profiles(count=10)
    devices = generate_devices(users, count=15)
    ip_ranges = generate_ip_ranges()

    # Statistics
    stats = {
        "total": 0,
        "granted": 0,
        "denied": 0,
        "reason_counts": {},
    }

    # For generating unique session IDs
    session_counter = 0

    try:
        for _ in range(iterations):
            # Generate a random access request
            user_id = random.choice(list(users.keys()))
            user = users[user_id]

            # Pick a device belonging to this user (or any; we'll ensure it's linked)
            # For realism, choose a device that might belong to the user, but we'll allow any.
            # To simulate, we'll pick a random device; for policy we just use its attributes.
            device_id = random.choice(list(devices.keys()))
            device = devices[device_id]

            # Generate IP – either from allowed or blocked country
            # 30% chance from blocked to test denial.
            if random.random() < 0.3:
                country = random.choice(["RU", "CN"])
            else:
                country = random.choice(["US", "IN", "EU"])
            ip = generate_ip(country)

            # Timestamp – simulate within last hour
            timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))

            # Evaluate
            granted, reason = evaluate_request(user, device, ip, timestamp, ip_ranges)

            # Generate session ID
            session_counter += 1
            session_id = f"ZTNA-{datetime.now().strftime('%Y%m%d%H%M%S')}-{session_counter:04d}"

            # Output live
            ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if granted:
                print_granted(session_id, user_id, device_id, ip, ts_str)
                stats["granted"] += 1
            else:
                print_denied(session_id, user_id, device_id, ip, ts_str, reason)
                stats["denied"] += 1
                stats["reason_counts"][reason] = stats["reason_counts"].get(reason, 0) + 1

            stats["total"] += 1

            # Pause to simulate real‑time stream
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nSimulation interrupted by user.")

    # Print final summary
    print_summary(stats)

# ---------- Command‑Line Interface ----------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Zero‑Trust Network Access Token Gate Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ztna_gate.py --iterations 100 --interval 0.2 --seed 123
  python ztna_gate.py --iterations 50
        """
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=20,
        help="Number of login attempts to simulate (default: 20)"
    )
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=0.5,
        help="Time delay between attempts in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=None,
        help="Random seed for reproducible runs (default: None)"
    )
    return parser.parse_args()

# ---------- Entry Point ----------
if __name__ == "__main__":
    args = parse_args()
    run_simulation(args.iterations, args.interval, args.seed)