#!/usr/bin/env python3
"""
Notifications: Slack and Microsoft Teams webhook integration.
"""

import json
import os
from urllib.request import Request, urlopen
from typing import Optional


def send_slack_notification(
    webhook_url: str,
    findings: dict,
    target: str,
    no_network: bool = False,
) -> bool:
    """
    Send a Slack notification with scan summary.
    Returns True on success.
    """
    if no_network or not webhook_url:
        return False

    secret_count = len(findings.get('secrets', []))
    total = sum(len(v) for v in findings.values())

    # Build message
    color = '#ff0000' if secret_count else '#36a64f'
    text = f"*JSVisor Scan Complete*\n"
    text += f"Target: `{target}`\n"
    text += f"Total findings: {total}\n"
    if secret_count:
        text += f":warning: *{secret_count} secret(s) detected!*\n"
        # List first 5 secrets (redacted)
        for item in findings.get('secrets', [])[:5]:
            val = item.get('value', '')
            text += f"  • {val}\n"

    payload = {
        "attachments": [{
            "color": color,
            "text": text,
            "footer": "JSVisor v4.0",
        }]
    }

    try:
        req = Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
        )
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def send_teams_notification(
    webhook_url: str,
    findings: dict,
    target: str,
    no_network: bool = False,
) -> bool:
    """Send a Microsoft Teams notification."""
    if no_network or not webhook_url:
        return False

    secret_count = len(findings.get('secrets', []))
    total = sum(len(v) for v in findings.values())

    color = 'FF0000' if secret_count else '00FF00'
    facts = [
        {"name": "Target", "value": target},
        {"name": "Total Findings", "value": str(total)},
        {"name": "Secrets Found", "value": str(secret_count)},
    ]

    payload = {
        "@type": "MessageCard",
        "themeColor": color,
        "summary": f"JSVisor: {total} findings",
        "sections": [{
            "activityTitle": "JSVisor Scan Complete",
            "facts": facts,
            "markdown": True,
        }],
    }

    try:
        req = Request(
            webhook_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
        )
        with urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def notify(findings: dict, target: str, no_network: bool = False):
    """
    Auto-detect webhook type from environment variables and send notification.
    Env vars: JSVISOR_SLACK_WEBHOOK, JSVISOR_TEAMS_WEBHOOK
    """
    slack_url = os.environ.get('JSVISOR_SLACK_WEBHOOK', '')
    teams_url = os.environ.get('JSVISOR_TEAMS_WEBHOOK', '')

    if slack_url:
        send_slack_notification(slack_url, findings, target, no_network)
    if teams_url:
        send_teams_notification(teams_url, findings, target, no_network)
