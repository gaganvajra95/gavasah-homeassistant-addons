#!/usr/bin/env python3
"""
GAVASAH Autonomous Dynamic Ingress Dispatcher
Routes wildcard subdomain HTTP/WebSocket connections to client reverse tunnels.
Provides high-security access suspension enforcement and branded contact prompt.
"""
import asyncio
import sqlite3
import time
import os
import html
import re
import json

DB_PATH = '/srv/gavasah-cloud/fleet.db'

SUSPENSION_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remote Access Disabled | GAVASAH Cloud Security</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #060913;
            color: #f1f5f9;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }}
        .suspension-card {{
            background: radial-gradient(circle at top right, rgba(239, 68, 68, 0.12), transparent 50%),
                        linear-gradient(180deg, #0e172a 0%, #090e1b 100%);
            border: 1px solid rgba(239, 68, 68, 0.35);
            border-radius: 20px;
            max-width: 520px;
            width: 100%;
            padding: 44px 36px;
            text-align: center;
            box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7), 0 0 35px rgba(239, 68, 68, 0.15);
        }}
        .icon-halo {{
            width: 76px;
            height: 76px;
            margin: 0 auto 22px;
            border-radius: 50%;
            background: rgba(239, 68, 68, 0.15);
            border: 2px solid rgba(239, 68, 68, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.25);
        }}
        .icon-halo svg {{
            width: 38px;
            height: 38px;
            stroke: #ef4444;
        }}
        .badge-status {{
            display: inline-block;
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1.2px;
            padding: 6px 14px;
            border-radius: 9999px;
            text-transform: uppercase;
            margin-bottom: 16px;
        }}
        h1 {{
            font-size: 23px;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        .gateway-tag {{
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 20px;
            font-family: monospace;
            background: rgba(15, 23, 42, 0.6);
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        p {{
            font-size: 14px;
            line-height: 1.6;
            color: #94a3b8;
            margin-bottom: 24px;
        }}
        .contact-box {{
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 18px 20px;
            margin-bottom: 26px;
            text-align: left;
        }}
        .contact-title {{
            font-size: 11px;
            font-weight: 700;
            color: #cbd5e1;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .contact-instruction {{
            font-size: 13.5px;
            color: #e2e8f0;
            line-height: 1.55;
        }}
        .footer-note {{
            font-size: 12px;
            color: #64748b;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}
    </style>
</head>
<body>
    <div class="suspension-card">
        <div class="icon-halo">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
        </div>
        <div class="badge-status">Remote Access Disabled</div>
        <h1>Remote Access Suspended</h1>
        <div class="gateway-tag">{client_display}</div>
        <p>
            Remote client access to this Home Assistant gateway has been disabled by the system administrator.
        </p>
        <div class="contact-box">
            <div class="contact-title">
                <span>📞 Next Steps</span>
            </div>
            <div class="contact-instruction">
                Please contact your <strong>Authorized Dealer ({dealer_name})</strong> or <strong>Manufacturer</strong> to restore remote access.
            </div>
        </div>
        <div class="footer-note">
            <span>🛡️</span> GAVASAH Cloud Security Platform
        </div>
    </div>
</body>
</html>"""

OFFLINE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Target Gateway Offline | GAVASAH Cloud</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: #060913;
            color: #f1f5f9;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            overflow-x: hidden;
            position: relative;
        }}
        body::before {{
            content: '';
            position: absolute;
            width: 600px;
            height: 600px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(245, 158, 11, 0.12) 0%, rgba(217, 119, 6, 0.03) 45%, transparent 70%);
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 0;
        }}
        .offline-card {{
            position: relative;
            z-index: 1;
            background: radial-gradient(circle at top right, rgba(245, 158, 11, 0.12), transparent 50%),
                        linear-gradient(180deg, #0e172a 0%, #090e1b 100%);
            border: 1px solid rgba(245, 158, 11, 0.35);
            border-radius: 20px;
            max-width: 520px;
            width: 100%;
            padding: 44px 36px;
            text-align: center;
            box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7), 0 0 35px rgba(245, 158, 11, 0.15);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
        }}
        .icon-halo {{
            width: 76px;
            height: 76px;
            margin: 0 auto 22px;
            border-radius: 50%;
            background: rgba(245, 158, 11, 0.15);
            border: 2px solid rgba(245, 158, 11, 0.4);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 30px rgba(245, 158, 11, 0.25);
            animation: pulse-ring 2.8s infinite ease-in-out;
        }}
        @keyframes pulse-ring {{
            0%, 100% {{ transform: scale(1); box-shadow: 0 0 30px rgba(245, 158, 11, 0.25); }}
            50% {{ transform: scale(1.05); box-shadow: 0 0 45px rgba(245, 158, 11, 0.45); }}
        }}
        .icon-halo svg {{
            width: 38px;
            height: 38px;
            stroke: #f59e0b;
        }}
        .badge-status {{
            display: inline-flex;
            align-items: center;
            gap: 7px;
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.4);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1.2px;
            padding: 6px 14px;
            border-radius: 9999px;
            text-transform: uppercase;
            margin-bottom: 16px;
        }}
        .badge-status::before {{
            content: '';
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #f59e0b;
            box-shadow: 0 0 8px #f59e0b;
            animation: blink 1.4s infinite;
        }}
        @keyframes blink {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.3; }}
        }}
        h1 {{
            font-size: 23px;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        .gateway-tag {{
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 20px;
            font-family: 'JetBrains Mono', monospace;
            background: rgba(15, 23, 42, 0.6);
            display: inline-block;
            padding: 4px 12px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        p {{
            font-size: 14px;
            line-height: 1.6;
            color: #94a3b8;
            margin-bottom: 24px;
        }}
        .contact-box {{
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 18px 20px;
            margin-bottom: 24px;
            text-align: left;
        }}
        .contact-title {{
            font-size: 11px;
            font-weight: 700;
            color: #cbd5e1;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .contact-instruction {{
            font-size: 13.5px;
            color: #cbd5e1;
            line-height: 1.6;
        }}
        .steps-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .steps-list li {{
            position: relative;
            padding-left: 20px;
            margin-bottom: 8px;
            font-size: 13px;
            color: #cbd5e1;
            line-height: 1.5;
        }}
        .steps-list li:last-child {{
            margin-bottom: 0;
        }}
        .steps-list li::before {{
            content: '•';
            position: absolute;
            left: 6px;
            color: #f59e0b;
            font-weight: bold;
            font-size: 16px;
            top: -2px;
        }}
        .btn-group {{
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 24px;
        }}
        .btn-primary-action {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%);
            color: #ffffff;
            border: none;
            padding: 12px 20px;
            border-radius: 12px;
            font-size: 13.5px;
            font-weight: 700;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
            box-shadow: 0 4px 14px rgba(217, 119, 6, 0.35);
        }}
        .btn-primary-action:hover {{
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(245, 158, 11, 0.5);
        }}
        .btn-secondary-action {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: rgba(15, 23, 42, 0.7);
            color: #94a3b8;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 10px 18px;
            border-radius: 12px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
        }}
        .btn-secondary-action:hover {{
            color: #e2e8f0;
            background: rgba(30, 41, 59, 0.85);
            border-color: rgba(245, 158, 11, 0.4);
        }}
        .copy-feedback {{
            font-size: 11.5px;
            color: #10b981;
            margin-top: 8px;
            display: none;
        }}
        .footer-note {{
            font-size: 12px;
            color: #64748b;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}
    </style>
</head>
<body>
    <div class="offline-card">
        <div class="icon-halo">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                <line x1="6" y1="18" x2="6.01" y2="18"></line>
                <line x1="18" y1="6" x2="18.01" y2="6"></line>
                <line x1="18" y1="18" x2="18.01" y2="18"></line>
                <line x1="1" y1="1" x2="23" y2="23"></line>
            </svg>
        </div>
        <div class="badge-status">Gateway Offline</div>
        <h1>Target Gateway Offline</h1>
        <div class="gateway-tag">{client_display}</div>
        <p>The Home Assistant instance is currently unreachable or the secure reverse tunnel is reconnecting.</p>
        <div class="contact-box">
            <div class="contact-title">
                <span>⚡ Troubleshooting Steps</span>
            </div>
            <div class="contact-instruction">
                <ul class="steps-list">
                    <li>Ensure your <strong>Gavasah Gateway</strong> hardware is powered on and connected to local internet.</li>
                    <li>If the gateway recently rebooted, please allow 30–60 seconds for the AutoSSH encrypted tunnel to reconnect.</li>
                    <li>Contact your <strong>Authorized Dealer ({dealer_name})</strong> or <strong>Manufacturer</strong> if connectivity is not restored.</li>
                </ul>
            </div>
        </div>
        <div class="btn-group">
            <button type="button" class="btn-primary-action" onclick="window.location.reload()">
                <span>🔄 Retry Connection Now</span>
            </button>
            <button type="button" class="btn-secondary-action" onclick="copyDiagnostics()">
                <span>📋 Copy Diagnostics for Support</span>
            </button>
        </div>
        <div id="copy-msg" class="copy-feedback">✓ Diagnostic telemetry copied to clipboard</div>
        <div class="footer-note">
            <span>🛡️</span> GAVASAH Cloud Security Platform
        </div>
    </div>
    <script>
        function copyDiagnostics() {{
            var diag = "Gateway: " + "{client_display}" + "\\n" +
                       "Dealer: " + "{dealer_name}" + "\\n" +
                       "Host: " + window.location.host + "\\n" +
                       "Timestamp: " + new Date().toISOString() + "\\n" +
                       "User-Agent: " + navigator.userAgent;
            navigator.clipboard.writeText(diag).then(function() {{
                var el = document.getElementById('copy-msg');
                if (el) {{
                    el.style.display = 'block';
                    setTimeout(function() {{ el.style.display = 'none'; }}, 3000);
                }}
            }}).catch(function() {{
                alert("Diagnostics:\\n" + diag);
            }});
        }}
    </script>
</body>
</html>"""

IP_BAN_HEALING_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Autonomous Self-Healing Active | GAVASAH Cloud</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #060913;
            color: #f1f5f9;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            overflow-x: hidden;
            position: relative;
        }
        body::before {
            content: '';
            position: absolute;
            width: 600px;
            height: 600px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.12) 0%, rgba(16, 185, 129, 0.04) 40%, transparent 70%);
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            pointer-events: none;
            z-index: 0;
        }
        .card {
            position: relative;
            z-index: 1;
            background: radial-gradient(circle at 85% 15%, rgba(6, 182, 212, 0.14), transparent 50%),
                        linear-gradient(180deg, rgba(15, 23, 42, 0.92) 0%, rgba(8, 14, 28, 0.96) 100%);
            border: 1px solid rgba(56, 189, 248, 0.28);
            border-radius: 24px;
            max-width: 540px;
            width: 100%;
            padding: 42px 36px 36px;
            text-align: center;
            box-shadow: 0 30px 70px -15px rgba(0, 0, 0, 0.8), 0 0 50px rgba(6, 182, 212, 0.12);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
        }
        .icon-wrap {
            position: relative;
            width: 76px;
            height: 76px;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .icon-halo {
            width: 76px;
            height: 76px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(6, 182, 212, 0.25) 0%, rgba(16, 185, 129, 0.1) 70%);
            border: 1.5px solid rgba(56, 189, 248, 0.45);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 35px rgba(6, 182, 212, 0.35);
            animation: pulse-ring 2.8s infinite ease-in-out;
        }
        @keyframes pulse-ring {
            0%, 100% { transform: scale(1); box-shadow: 0 0 35px rgba(6, 182, 212, 0.35); }
            50% { transform: scale(1.06); box-shadow: 0 0 50px rgba(16, 185, 129, 0.5); }
        }
        .icon-halo svg { width: 36px; height: 36px; stroke: #38bdf8; }
        .badge-status {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            background: rgba(6, 182, 212, 0.12);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.35);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1px;
            padding: 5px 14px;
            border-radius: 9999px;
            text-transform: uppercase;
            margin-bottom: 14px;
        }
        .badge-status::before {
            content: '';
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
            animation: blink 1.4s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        h1 {
            font-size: 22px;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 8px;
            letter-spacing: -0.3px;
        }
        .sub-desc {
            font-size: 13.5px;
            line-height: 1.55;
            color: #94a3b8;
            margin-bottom: 20px;
        }
        .gateway-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 6px 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            color: #e2e8f0;
            margin-bottom: 22px;
        }
        .gateway-pill strong { color: #38bdf8; font-weight: 600; }
        
        /* Timeline Steps */
        .timeline-box {
            background: rgba(11, 19, 41, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.07);
            border-radius: 14px;
            padding: 16px 18px;
            text-align: left;
            margin-bottom: 24px;
        }
        .timeline-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            font-size: 12.5px;
            padding: 7px 0;
            color: #cbd5e1;
        }
        .timeline-item:not(:last-child) {
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        .timeline-dot {
            width: 18px;
            height: 18px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            flex-shrink: 0;
            margin-top: 1px;
        }
        .dot-done { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
        .dot-active { background: rgba(6, 182, 212, 0.25); color: #38bdf8; border: 1px solid rgba(6, 182, 212, 0.6); animation: pulse-dot 1.2s infinite; }
        .dot-pend { background: rgba(100, 116, 139, 0.2); color: #64748b; border: 1px solid rgba(100, 116, 139, 0.3); }
        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        /* Circular Timer */
        .timer-container {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            margin-bottom: 24px;
        }
        .timer-svg {
            transform: rotate(-90deg);
        }
        .timer-bg {
            fill: none;
            stroke: rgba(255, 255, 255, 0.08);
            stroke-width: 4;
        }
        .timer-fill {
            fill: none;
            stroke: url(#timerGrad);
            stroke-width: 4;
            stroke-linecap: round;
            stroke-dasharray: 226;
            stroke-dashoffset: 0;
            transition: stroke-dashoffset 0.95s linear;
        }
        .timer-info {
            text-align: left;
        }
        .timer-val {
            font-size: 20px;
            font-weight: 800;
            color: #ffffff;
            font-family: 'JetBrains Mono', monospace;
        }
        .timer-sub {
            font-size: 11.5px;
            color: #64748b;
            margin-top: 2px;
        }

        /* Action Buttons */
        .btn-group {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .btn-primary-action {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: linear-gradient(135deg, #0284c7 0%, #06b6d4 100%);
            color: #ffffff;
            border: none;
            padding: 12px 20px;
            border-radius: 12px;
            font-size: 13.5px;
            font-weight: 700;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
            box-shadow: 0 4px 14px rgba(2, 132, 199, 0.35);
        }
        .btn-primary-action:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(6, 182, 212, 0.5);
        }
        .btn-secondary-action {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: rgba(15, 23, 42, 0.7);
            color: #94a3b8;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 10px 18px;
            border-radius: 12px;
            font-size: 12.5px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
        }
        .btn-secondary-action:hover {
            color: #e2e8f0;
            background: rgba(30, 41, 59, 0.85);
            border-color: rgba(56, 189, 248, 0.3);
        }
        .copy-feedback {
            font-size: 11.5px;
            color: #10b981;
            margin-top: 8px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-wrap">
            <div class="icon-halo">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <path d="m9 12 2 2 4-4"></path>
                </svg>
            </div>
        </div>
        <div class="badge-status">Loopback Protection Active</div>
        <h1>Gavasah Gateway Recovery</h1>
        <div class="sub-desc">
            Home Assistant Core restricted tunnel loopback traffic (HTTP 403). GAVASAH Cloud has autonomously dispatched unban directives and trusted reverse proxy provisioning.
        </div>

        <div class="gateway-pill">
            <span>Gateway:</span>
            <strong>{client_display}</strong>
        </div>

        <div class="timeline-box">
            <div class="timeline-item">
                <span class="timeline-dot dot-done">✓</span>
                <div>
                    <div style="font-weight: 600; color: #f8fafc;">Autonomous Unban Dispatched</div>
                    <div style="color: #64748b; font-size: 11.5px;">Flushing loopback ban from ip_bans.yaml</div>
                </div>
            </div>
            <div class="timeline-item">
                <span class="timeline-dot dot-active">⚡</span>
                <div>
                    <div style="font-weight: 600; color: #38bdf8;">Reverse Proxy Headers Sync</div>
                    <div style="color: #64748b; font-size: 11.5px;">Validating trusted_proxies & disabling loopback ban rule</div>
                </div>
            </div>
            <div class="timeline-item">
                <span class="timeline-dot dot-pend">⋯</span>
                <div>
                    <div style="font-weight: 600; color: #94a3b8;">Automatic Ingress Reconnection</div>
                    <div style="color: #64748b; font-size: 11.5px;">Reloading session into Home Assistant Core GUI</div>
                </div>
            </div>
        </div>

        <div class="timer-container">
            <svg class="timer-svg" width="76" height="76" viewBox="0 0 76 76">
                <defs>
                    <linearGradient id="timerGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#06b6d4" />
                        <stop offset="100%" stop-color="#10b981" />
                    </linearGradient>
                </defs>
                <circle class="timer-bg" cx="38" cy="38" r="34" />
                <circle class="timer-fill" id="timer-circle" cx="38" cy="38" r="34" />
            </svg>
            <div class="timer-info">
                <div class="timer-val"><span id="countdown">15</span>s</div>
                <div class="timer-sub">Auto-reconnecting to GUI...</div>
            </div>
        </div>

        <div class="btn-group">
            <button type="button" class="btn-primary-action" onclick="reconnectNow()">
                <span>⚡ Reconnect to Gateway Now</span>
            </button>
            <button type="button" class="btn-secondary-action" onclick="bypassDirect()">
                <span>👁️ Direct Upstream Pass-Through (Bypass Filter)</span>
            </button>
            <button type="button" class="btn-secondary-action" onclick="copyDiagnostics()">
                <span>📋 Copy Diagnostics for Support</span>
            </button>
        </div>
        <div id="copy-msg" class="copy-feedback">✓ Diagnostic telemetry copied to clipboard</div>
    </div>

    <script>
        var total = 15;
        var left = total;
        var circle = document.getElementById('timer-circle');
        var cd = document.getElementById('countdown');
        var maxOffset = 213.6; // 2 * PI * 34

        var timer = setInterval(function() {
            left -= 1;
            if (left <= 0) {
                clearInterval(timer);
                if (cd) cd.innerText = '0';
                if (circle) circle.style.strokeDashoffset = maxOffset;
                window.location.reload();
            } else {
                if (cd) cd.innerText = left;
                if (circle) {
                    var progress = (total - left) / total;
                    circle.style.strokeDashoffset = progress * maxOffset;
                }
            }
        }, 1000);

        function reconnectNow() {
            window.location.reload();
        }

        function bypassDirect() {
            document.cookie = 'gavasah_bypass_ban=1; path=/; max-age=3600';
            var currentUrl = new URL(window.location.href);
            currentUrl.searchParams.set('bypass_ban_interceptor', '1');
            window.location.href = currentUrl.toString();
        }

        function copyDiagnostics() {
            var diag = "GAVASAH GATEWAY DIAGNOSTICS\\n" +
                       "Gateway: {client_display} ({client_id})\\n" +
                       "Domain: {client_domain}\\n" +
                       "Event: Loopback Reverse Tunnel Ingress Restriction (HTTP 403)\\n" +
                       "Timestamp: " + new Date().toISOString() + "\\n" +
                       "User-Agent: " + navigator.userAgent;
            navigator.clipboard.writeText(diag).then(function() {
                var el = document.getElementById('copy-msg');
                if (el) {
                    el.style.display = 'block';
                    setTimeout(function() { el.style.display = 'none'; }, 3000);
                }
            }).catch(function() {
                alert("Diagnostics:\\n" + diag);
            });
        }
    </script>
</body>
</html>"""

_CLIENT_CACHE = {}
_CACHE_TTL = 3.0  # 3-second in-memory lookup cache to eliminate SQLite churn

def get_client_info(slug):
    """Fetches real-time client status directly from SQLite WAL database with 3s TTL caching."""
    now = time.time()
    cached = _CLIENT_CACHE.get(slug)
    if cached and (now - cached[0] < _CACHE_TTL):
        return cached[1]

    # Periodic cache cleanup to prevent memory growth
    if len(_CLIENT_CACHE) > 1000:
        for k in list(_CLIENT_CACHE.keys()):
            if now - _CLIENT_CACHE[k][0] > 10.0:
                _CLIENT_CACHE.pop(k, None)

    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT c.client_id, c.name, c.dealer_id, c.dealer_name, c.dashboard_port, c.remote_enabled, "
            "d.status AS dealer_status "
            "FROM clients c "
            "LEFT JOIN dealers d ON c.dealer_id = d.id "
            "WHERE c.client_id = ? OR c.domain = ?",
            (slug, f"{slug}.gavasah.com")
        )
        row = cur.fetchone()

        if not row:
            clean_slug = re.sub(r'^(mr|mrs|ms|dr)-', '', slug.lower())
            cur.execute(
                "SELECT c.client_id, c.name, c.dealer_id, c.dealer_name, c.dashboard_port, c.remote_enabled, c.domain, "
                "d.status AS dealer_status "
                "FROM clients c "
                "LEFT JOIN dealers d ON c.dealer_id = d.id"
            )
            for r in cur.fetchall():
                cid = (r['client_id'] or '').lower()
                clean_cid = re.sub(r'^(mr|mrs|ms|dr)-', '', cid)
                if (clean_slug == clean_cid or 
                    clean_cid.startswith(clean_slug) or 
                    clean_slug.startswith(clean_cid)):
                    row = r
                    break
                name_slug = re.sub(r'[^a-z0-9]+', '-', (r['name'] or '').lower()).strip('-')
                clean_name = re.sub(r'^(mr|mrs|ms|dr)-', '', name_slug)
                if (clean_slug == clean_name or 
                    clean_name.startswith(clean_slug) or 
                    clean_slug.startswith(clean_name)):
                    row = r
                    break

        conn.close()

        if not row:
            res = {'status': 'NOT_FOUND', 'slug': slug}
            _CLIENT_CACHE[slug] = (now, res)
            return res

        # 1. Enforce Dealer Account Suspension (§3.C.1)
        dealer_status = (row['dealer_status'] or 'active').lower() if row['dealer_id'] != 'owner_master' else 'active'
        if dealer_status != 'active':
            res = {
                'status': 'SUSPENDED',
                'client_id': row['client_id'],
                'name': row['name'] or row['client_id'],
                'dealer_name': row['dealer_name'] or 'Authorized Dealer',
                'port': None
            }
            _CLIENT_CACHE[slug] = (now, res)
            return res

        # 2. Enforce Site Remote Toggle Suspension
        is_enabled = bool(row['remote_enabled'])
        if not is_enabled:
            res = {
                'status': 'SUSPENDED',
                'client_id': row['client_id'],
                'name': row['name'] or row['client_id'],
                'dealer_name': row['dealer_name'] or 'Authorized Dealer',
                'port': None
            }
            _CLIENT_CACHE[slug] = (now, res)
            return res

        port = int(row['dashboard_port']) if row['dashboard_port'] else None
        res = {
            'status': 'ACTIVE',
            'client_id': row['client_id'],
            'name': row['name'] or row['client_id'],
            'dealer_name': row['dealer_name'] or 'Authorized Dealer',
            'port': port
        }
        _CLIENT_CACHE[slug] = (now, res)
        if row['client_id'] and row['client_id'] != slug:
            _CLIENT_CACHE[row['client_id']] = (now, res)
        return res
    except Exception as e:
        print(f"[!] Dispatcher DB lookup error for {slug}: {e}", flush=True)
        return {'status': 'ERROR', 'error': str(e), 'slug': slug}

def queue_client_command(client_id, cmd_dict):
    """Queues an autonomous recovery command for the client to execute on its next pulse."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5.0)
        conn.execute(
            "UPDATE clients SET pending_command = ? WHERE (client_id = ? OR domain LIKE ?) AND (pending_command IS NULL OR pending_command = '')",
            (json.dumps(cmd_dict), client_id, f"{client_id}%")
        )
        conn.commit()
        conn.close()
        print(f"[*] Autonomous Self-Healer queued '{cmd_dict.get('action')}' for client '{client_id}'", flush=True)
    except Exception as e:
        print(f"[!] Dispatcher error queuing command for {client_id}: {e}", flush=True)

def build_http_response(status_code, status_text, body_html):
    crlf = b"\r\n"
    body_bytes = body_html.encode('utf-8')
    headers = [
        f"HTTP/1.1 {status_code} {status_text}".encode('ascii'),
        b"Content-Type: text/html; charset=utf-8",
        f"Content-Length: {len(body_bytes)}".encode('ascii'),
        b"Connection: close",
        b"Cache-Control: no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0",
        b"Pragma: no-cache",
        b"Expires: 0"
    ]
    
    header_block = crlf.join(headers) + crlf + crlf
    return header_block + body_bytes

def strip_untrusted_forwarded_headers(raw_data):
    """
    Strips X-Forwarded-For header so Home Assistant Core never rejects
    with '400: Bad Request' when trusted_proxies has not been configured.
    """
    try:
        sep = b"\r\n\r\n"
        if sep not in raw_data:
            return raw_data
        hdr_part, body_part = raw_data.split(sep, 1)
        lines = hdr_part.split(b"\r\n")
        clean_lines = [l for l in lines if not l.lower().startswith(b"x-forwarded-for:")]
        return b"\r\n".join(clean_lines) + sep + body_part
    except Exception:
        return raw_data

import ssl

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# In-memory protocol cache: target_port -> bool (True = https, False = plain http)
PORT_SSL_CACHE = {
    10011: True  # vajju-vja-house uses SSL Let's Encrypt locally
}

async def connect_upstream(target_port, clean_initial_data):
    """
    Connects to target reverse tunnel port, dynamically handling both plain HTTP
    and HTTPS (TLS) Home Assistant instances without manual configuration.
    """
    cached_ssl = PORT_SSL_CACHE.get(target_port)

    # 1. Known SSL
    if cached_ssl is True:
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', target_port, ssl=SSL_CTX),
                timeout=4.0
            )
            up_writer.write(clean_initial_data)
            await up_writer.drain()
            return up_reader, up_writer, None
        except Exception:
            return None, None, None

    # 2. Known Plain HTTP
    if cached_ssl is False:
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', target_port, ssl=None),
                timeout=4.0
            )
            up_writer.write(clean_initial_data)
            await up_writer.drain()
            return up_reader, up_writer, None
        except Exception:
            return None, None, None

    # 3. Unknown: Try plain HTTP first with fast probe
    try:
        up_reader, up_writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', target_port, ssl=None),
            timeout=3.0
        )
        up_writer.write(clean_initial_data)
        await up_writer.drain()

        # Check if remote server instantly drops/closes plain HTTP socket (behavior of SSL server receiving non-TLS bytes)
        is_ssl = False
        try:
            first_chunk = await asyncio.wait_for(up_reader.read(65536), timeout=0.15)
            if first_chunk == b"":
                # Server closed immediately -> port is HTTPS!
                is_ssl = True
            else:
                # Plain HTTP responded with data!
                PORT_SSL_CACHE[target_port] = False
                return up_reader, up_writer, first_chunk
        except asyncio.TimeoutError:
            # Server accepted the connection and is processing the request normally (Plain HTTP)!
            PORT_SSL_CACHE[target_port] = False
            return up_reader, up_writer, None

        if is_ssl:
            up_writer.close()
            try:
                await up_writer.wait_closed()
            except Exception:
                pass

            ssl_reader, ssl_writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', target_port, ssl=SSL_CTX),
                timeout=4.0
            )
            ssl_writer.write(clean_initial_data)
            await ssl_writer.drain()
            PORT_SSL_CACHE[target_port] = True
            return ssl_reader, ssl_writer, None
    except Exception:
        # Fallback to SSL if initial plain connection failed completely
        try:
            ssl_reader, ssl_writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', target_port, ssl=SSL_CTX),
                timeout=4.0
            )
            ssl_writer.write(clean_initial_data)
            await ssl_writer.drain()
            PORT_SSL_CACHE[target_port] = True
            return ssl_reader, ssl_writer, None
        except Exception:
            pass
        return None, None, None

async def handle_connection(reader, writer):
    try:
        initial_data = await reader.read(4096)
        if not initial_data:
            writer.close()
            return

        lines = initial_data.split(bytes([13, 10]))
        slug = None
        for l in lines:
            if l.lower().startswith(b"host:"):
                host_str = l[5:].decode('ascii', errors='ignore').strip()
                if ':' in host_str:
                    host_str = host_str.split(':')[0]
                slug = host_str[:-len('.gavasah.com')] if host_str.endswith('.gavasah.com') else host_str
                break

        if not slug:
            writer.close()
            return

        client_info = get_client_info(slug)
        status = client_info.get('status')
        client_display = html.escape(client_info.get('name') or slug)
        dealer_name = html.escape(client_info.get('dealer_name') or 'Authorized Dealer')

        # 1. Suspended / Remote Access Disabled -> Return 200 OK with Restricted Card
        if status == 'SUSPENDED':
            resp_html = SUSPENSION_HTML_TEMPLATE.format(
                client_display=client_display,
                dealer_name=dealer_name
            )
            resp = build_http_response(200, "OK", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        # 2. Not Registered
        if status in ['NOT_FOUND', 'ERROR']:
            resp_html = f"""<!DOCTYPE html><html><body style="background:#060913;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;"><div style="text-align:center;max-width:480px;padding:30px;"><h2 style="color:#ef4444;">Gateway Not Found</h2><p style="color:#94a3b8;line-height:1.6;">Gateway <code>{html.escape(slug)}</code> is not registered on GAVASAH Cloud.<br><br>Please contact your Authorized Dealer or Manufacturer.</p></div></body></html>"""
            resp = build_http_response(404, "Not Found", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        # 3. Active - Forward to target reverse tunnel port
        target_port = client_info.get('port')
        if not target_port:
            resp_html = OFFLINE_HTML_TEMPLATE.format(
                client_display=client_display,
                dealer_name=dealer_name
            )
            resp = build_http_response(502, "Bad Gateway", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        # Filter out X-Forwarded-For so Home Assistant Core never throws 400 Bad Request
        clean_initial_data = strip_untrusted_forwarded_headers(initial_data)

        up_reader, up_writer, primed_chunk = await connect_upstream(target_port, clean_initial_data)
        if not up_reader or not up_writer:
            resp_html = OFFLINE_HTML_TEMPLATE.format(
                client_display=client_display,
                dealer_name=dealer_name
            )
            resp = build_http_response(503, "Service Unavailable", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            return

        # Check for user-directed bypass (e.g. cookie or query parameter)
        is_bypass = (
            b"bypass_ban_interceptor=1" in initial_data or
            b"gavasah_bypass_ban=1" in initial_data or
            b"X-Gavasah-Bypass-Ban" in initial_data
        )

        # Check the first upstream response buffer for 403 Forbidden (Home Assistant loopback IP Ban)
        first_resp_chunk = primed_chunk
        if not first_resp_chunk:
            try:
                first_resp_chunk = await asyncio.wait_for(up_reader.read(65536), timeout=2.5)
            except Exception:
                first_resp_chunk = b""

        if not is_bypass and first_resp_chunk and (b"403 Forbidden" in first_resp_chunk or b"403: Forbidden" in first_resp_chunk):
            cid = client_info.get('client_id') or slug
            queue_client_command(cid, {"action": "unban_and_fix", "restart_core": True, "reason": "ingress_403_detected"})
            
            client_display = html.escape(client_info.get('name') or slug)
            client_domain = html.escape(client_info.get('domain') or (slug + '.gavasah.com'))
            resp_html = (
                IP_BAN_HEALING_HTML_TEMPLATE
                .replace("{client_display}", client_display)
                .replace("{client_domain}", client_domain)
                .replace("{client_id}", html.escape(cid))
            )
            resp = build_http_response(200, "OK", resp_html)
            writer.write(resp)
            await writer.drain()
            writer.close()
            try:
                up_writer.close()
                await up_writer.wait_closed()
            except Exception:
                pass
            return

        # Pass through normal response chunk if one was read
        if first_resp_chunk:
            writer.write(first_resp_chunk)
            await writer.drain()

        async def pipe(src, dst):
            try:
                while True:
                    buf = await src.read(65536)
                    if not buf:
                        break
                    dst.write(buf)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try: dst.close()
                except: pass

        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
    except Exception:
        pass
    finally:
        try: writer.close()
        except: pass

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 10000)
    print("[*] GAVASAH Autonomous Dynamic Ingress Dispatcher active on port 10000...", flush=True)
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())
