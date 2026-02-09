#!/usr/bin/env python3
"""
Kali-GPT v4.1 - Real-time Dashboard Server

Serves the web dashboard and integrates with the API server.

Usage:
    python3 dashboard_server.py
    
Then open: http://localhost:8080

The dashboard connects to the API server at http://localhost:8000
Make sure to start the API server first.
"""

import os
import sys
from pathlib import Path

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError:
    print("FastAPI not installed. Run: pip install fastapi uvicorn")
    sys.exit(1)


# Configuration
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8080"))
API_URL = os.getenv("API_URL", "http://localhost:8000")


# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent


# Create FastAPI app
app = FastAPI(
    title="Kali-GPT Dashboard",
    description="Real-time penetration testing dashboard",
    version="4.1.0"
)


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dashboard HTML
DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali-GPT Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e14;
            --bg-secondary: #0d1117;
            --bg-tertiary: #161b22;
            --bg-card: #1a1f26;
            --border-color: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
            --accent-cyan: #39c5cf;
            --accent-orange: #f0883e;
            --glow-green: rgba(63, 185, 80, 0.3);
            --glow-red: rgba(248, 81, 73, 0.3);
            --glow-blue: rgba(88, 166, 255, 0.3);
            --gradient-cyber: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0a0e14 100%);
            --gradient-accent: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Space Grotesk', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        .bg-grid {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background-image: 
                linear-gradient(rgba(88, 166, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(88, 166, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }

        .header {
            position: fixed;
            top: 0; left: 0; right: 0;
            height: 64px;
            background: rgba(13, 17, 23, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            padding: 0 24px;
            z-index: 1000;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 700;
            font-size: 1.5rem;
        }

        .logo-icon {
            width: 40px; height: 40px;
            background: var(--gradient-accent);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .logo-text {
            background: var(--gradient-accent);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .header-status {
            margin-left: auto;
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border-radius: 20px;
            font-size: 0.85rem;
        }

        .status-dot {
            width: 8px; height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
            animation: pulse 2s infinite;
        }

        .status-dot.offline { background: var(--accent-red); animation: none; }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .main {
            margin-top: 64px;
            display: flex;
            min-height: calc(100vh - 64px);
            position: relative;
            z-index: 1;
        }

        .sidebar {
            width: 240px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            padding: 20px 0;
            position: fixed;
            top: 64px; left: 0; bottom: 0;
        }

        .nav-section { margin-bottom: 24px; }

        .nav-title {
            padding: 0 20px;
            margin-bottom: 8px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 20px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .nav-item.active {
            background: rgba(88, 166, 255, 0.1);
            color: var(--accent-blue);
            border-left-color: var(--accent-blue);
        }

        .content {
            flex: 1;
            margin-left: 240px;
            padding: 24px;
        }

        .page-header { margin-bottom: 24px; }
        .page-title { font-size: 1.75rem; font-weight: 700; margin-bottom: 8px; }
        .page-subtitle { color: var(--text-secondary); }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
        }

        .stat-card.green::before { background: var(--accent-green); }
        .stat-card.blue::before { background: var(--accent-blue); }
        .stat-card.yellow::before { background: var(--accent-yellow); }
        .stat-card.red::before { background: var(--accent-red); }

        .stat-label { font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 8px; }
        .stat-value { font-size: 2rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 24px;
        }

        .card-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .card-title { font-weight: 600; display: flex; align-items: center; gap: 8px; }
        .card-body { padding: 20px; }

        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        .scan-item {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            transition: background 0.2s;
        }

        .scan-item:last-child { border-bottom: none; }
        .scan-item:hover { background: var(--bg-tertiary); }

        .scan-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }

        .scan-target { font-weight: 600; font-family: 'JetBrains Mono', monospace; }

        .scan-status {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .scan-status.running { background: rgba(88, 166, 255, 0.2); color: var(--accent-blue); }
        .scan-status.completed { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }
        .scan-status.failed { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        .scan-status.pending { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }

        .progress-bar {
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
            margin-bottom: 8px;
        }

        .progress-fill {
            height: 100%;
            background: var(--gradient-accent);
            border-radius: 3px;
            transition: width 0.3s;
        }

        .scan-meta {
            display: flex;
            gap: 16px;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }

        .finding-item {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .finding-severity {
            width: 10px; height: 10px;
            border-radius: 50%;
        }

        .finding-severity.critical { background: var(--accent-red); box-shadow: 0 0 10px var(--glow-red); }
        .finding-severity.high { background: var(--accent-orange); }
        .finding-severity.medium { background: var(--accent-yellow); }
        .finding-severity.low { background: var(--accent-blue); }
        .finding-severity.info { background: var(--text-muted); }

        .finding-content { flex: 1; }
        .finding-title { font-size: 0.9rem; margin-bottom: 4px; }
        .finding-meta { font-size: 0.75rem; color: var(--text-secondary); }

        .terminal {
            background: #000;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }

        .terminal-header {
            background: var(--bg-tertiary);
            padding: 8px 12px;
            display: flex;
            gap: 8px;
        }

        .terminal-dot { width: 12px; height: 12px; border-radius: 50%; }
        .terminal-dot.red { background: #ff5f56; }
        .terminal-dot.yellow { background: #ffbd2e; }
        .terminal-dot.green { background: #27c93f; }

        .terminal-body {
            padding: 16px;
            max-height: 300px;
            overflow-y: auto;
            line-height: 1.6;
        }

        .terminal-line { margin-bottom: 4px; }
        .terminal-line .prompt { color: var(--accent-green); }
        .terminal-line .output { color: var(--text-secondary); }
        .terminal-line .success { color: var(--accent-green); }
        .terminal-line .error { color: var(--accent-red); }

        .btn {
            padding: 10px 20px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
        }

        .btn-primary {
            background: var(--gradient-accent);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px var(--glow-blue);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }

        .form-group { margin-bottom: 16px; }
        .form-label { display: block; margin-bottom: 8px; font-size: 0.85rem; color: var(--text-secondary); }

        .form-input, .form-select {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--accent-blue);
        }

        .modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s;
        }

        .modal-overlay.active { opacity: 1; visibility: visible; }

        .modal {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            width: 500px;
            max-width: 90%;
            transform: scale(0.9);
            transition: transform 0.3s;
        }

        .modal-overlay.active .modal { transform: scale(1); }

        .modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
        }

        .modal-title { font-size: 1.2rem; font-weight: 600; }

        .modal-close {
            width: 32px; height: 32px;
            border-radius: 8px;
            background: var(--bg-tertiary);
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1.2rem;
        }

        .modal-body { padding: 20px; }

        .modal-footer {
            padding: 16px 20px;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }

        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
        }

        .empty-state-icon { font-size: 3rem; margin-bottom: 16px; opacity: 0.5; }
        .empty-state-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 8px; color: var(--text-primary); }

        .toast-container {
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 3000;
        }

        .toast {
            padding: 16px 20px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 12px;
            animation: slideIn 0.3s ease;
        }

        .toast.success { border-left: 4px solid var(--accent-green); }
        .toast.error { border-left: 4px solid var(--accent-red); }
        .toast.info { border-left: 4px solid var(--accent-blue); }

        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .connection-lost {
            position: fixed;
            top: 64px;
            left: 0; right: 0;
            background: var(--accent-red);
            color: white;
            padding: 12px;
            text-align: center;
            font-weight: 600;
            z-index: 999;
            display: none;
        }

        .connection-lost.show { display: block; }

        @media (max-width: 1200px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .content { margin-left: 0; }
            .stats-grid, .grid-2 { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    <div class="connection-lost" id="connectionLost">⚠️ Connection to API server lost</div>

    <header class="header">
        <div class="logo">
            <div class="logo-icon">🤖</div>
            <span class="logo-text">KALI-GPT</span>
        </div>
        <div class="header-status">
            <div class="status-indicator">
                <span class="status-dot" id="statusDot"></span>
                <span id="statusText">Connecting...</span>
            </div>
            <button class="btn btn-primary" onclick="openModal('newScanModal')">+ New Scan</button>
        </div>
    </header>

    <main class="main">
        <nav class="sidebar">
            <div class="nav-section">
                <div class="nav-title">Overview</div>
                <div class="nav-item active" data-page="dashboard">📊 Dashboard</div>
                <div class="nav-item" data-page="scans">🔍 Scans</div>
                <div class="nav-item" data-page="findings">🐛 Findings</div>
            </div>
            <div class="nav-section">
                <div class="nav-title">Manage</div>
                <div class="nav-item" data-page="targets">🎯 Targets</div>
            </div>
        </nav>

        <div class="content">
            <div id="page-dashboard">
                <div class="page-header">
                    <h1 class="page-title">Dashboard</h1>
                    <p class="page-subtitle">Real-time penetration testing overview</p>
                </div>

                <div class="stats-grid">
                    <div class="stat-card blue">
                        <div class="stat-label">Active Scans</div>
                        <div class="stat-value" id="statActive">0</div>
                    </div>
                    <div class="stat-card green">
                        <div class="stat-label">Targets</div>
                        <div class="stat-value" id="statTargets">0</div>
                    </div>
                    <div class="stat-card yellow">
                        <div class="stat-label">Total Findings</div>
                        <div class="stat-value" id="statFindings">0</div>
                    </div>
                    <div class="stat-card red">
                        <div class="stat-label">Critical</div>
                        <div class="stat-value" id="statCritical">0</div>
                    </div>
                </div>

                <div class="grid-2">
                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">🔍 Active Scans</span>
                            <button class="btn btn-secondary" onclick="loadScans()">Refresh</button>
                        </div>
                        <div class="card-body" id="activeScans">
                            <div class="empty-state">
                                <div class="empty-state-icon">🔍</div>
                                <div class="empty-state-title">No active scans</div>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <span class="card-title">💻 Live Output</span>
                        </div>
                        <div class="terminal">
                            <div class="terminal-header">
                                <span class="terminal-dot red"></span>
                                <span class="terminal-dot yellow"></span>
                                <span class="terminal-dot green"></span>
                            </div>
                            <div class="terminal-body" id="terminal">
                                <div class="terminal-line">
                                    <span class="prompt">$ </span>
                                    <span class="output">Waiting for scan activity...</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🐛 Recent Findings</span>
                    </div>
                    <div class="card-body" style="padding: 0;" id="recentFindings">
                        <div class="empty-state">
                            <div class="empty-state-icon">🔒</div>
                            <div class="empty-state-title">No findings yet</div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="page-targets" style="display:none;">
                <div class="page-header">
                    <h1 class="page-title">Targets</h1>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🎯 All Targets</span>
                        <button class="btn btn-primary" onclick="openModal('newTargetModal')">+ Add Target</button>
                    </div>
                    <div class="card-body" id="targetsList">
                        <div class="empty-state">
                            <div class="empty-state-icon">🎯</div>
                            <div class="empty-state-title">No targets</div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="page-scans" style="display:none;">
                <div class="page-header">
                    <h1 class="page-title">Scans</h1>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🔍 All Scans</span>
                    </div>
                    <div class="card-body" id="allScans">
                        <div class="empty-state">
                            <div class="empty-state-icon">🔍</div>
                            <div class="empty-state-title">No scans</div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="page-findings" style="display:none;">
                <div class="page-header">
                    <h1 class="page-title">Findings</h1>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">🐛 All Findings</span>
                    </div>
                    <div class="card-body" style="padding:0;" id="allFindings">
                        <div class="empty-state">
                            <div class="empty-state-icon">🔒</div>
                            <div class="empty-state-title">No findings</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- New Scan Modal -->
    <div class="modal-overlay" id="newScanModal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">🔍 New Scan</h3>
                <button class="modal-close" onclick="closeModal('newScanModal')">×</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Target</label>
                    <select class="form-select" id="scanTarget"></select>
                </div>
                <div class="form-group">
                    <label class="form-label">Scan Type</label>
                    <select class="form-select" id="scanType">
                        <option value="quick">Quick</option>
                        <option value="standard" selected>Standard</option>
                        <option value="full">Full</option>
                        <option value="web">Web App</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('newScanModal')">Cancel</button>
                <button class="btn btn-primary" onclick="startScan()">Start</button>
            </div>
        </div>
    </div>

    <!-- New Target Modal -->
    <div class="modal-overlay" id="newTargetModal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">🎯 Add Target</h3>
                <button class="modal-close" onclick="closeModal('newTargetModal')">×</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Name</label>
                    <input type="text" class="form-input" id="targetName" placeholder="Production Server">
                </div>
                <div class="form-group">
                    <label class="form-label">Host / IP</label>
                    <input type="text" class="form-input" id="targetHost" placeholder="10.10.10.5">
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('newTargetModal')">Cancel</button>
                <button class="btn btn-primary" onclick="createTarget()">Add</button>
            </div>
        </div>
    </div>

    <div class="toast-container" id="toasts"></div>

    <script>
        const API = 'API_URL_PLACEHOLDER';
        let targets = [], scans = [], findings = [];

        async function api(endpoint, method = 'GET', data = null) {
            const opts = { method, headers: { 'Content-Type': 'application/json' } };
            if (data) opts.body = JSON.stringify(data);
            try {
                const r = await fetch(API + endpoint, opts);
                if (!r.ok) throw new Error((await r.json()).detail || 'Error');
                return await r.json();
            } catch (e) {
                if (e.message === 'Failed to fetch') {
                    document.getElementById('connectionLost').classList.add('show');
                    document.getElementById('statusDot').classList.add('offline');
                    document.getElementById('statusText').textContent = 'Offline';
                }
                throw e;
            }
        }

        async function init() {
            try {
                const h = await api('/health');
                document.getElementById('connectionLost').classList.remove('show');
                document.getElementById('statusDot').classList.remove('offline');
                document.getElementById('statusText').textContent = 'v' + h.version;
                await Promise.all([loadStats(), loadTargets(), loadScans(), loadFindings()]);
                setInterval(() => { loadStats(); loadScans(); loadFindings(); }, 10000);
                toast('Connected', 'success');
            } catch (e) {
                toast('Failed to connect', 'error');
            }
        }

        async function loadStats() {
            try {
                const s = await api('/stats');
                document.getElementById('statTargets').textContent = s.total_targets || 0;
                document.getElementById('statFindings').textContent = s.total_findings || 0;
                document.getElementById('statCritical').textContent = s.findings_by_severity?.critical || 0;
                document.getElementById('statActive').textContent = scans.filter(x => x.status === 'running').length;
            } catch (e) {}
        }

        async function loadTargets() {
            try {
                targets = await api('/targets');
                const sel = document.getElementById('scanTarget');
                sel.innerHTML = targets.map(t => `<option value="${t.id}">${t.name} (${t.host})</option>`).join('');
                
                const list = document.getElementById('targetsList');
                if (targets.length === 0) {
                    list.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🎯</div><div class="empty-state-title">No targets</div></div>';
                } else {
                    list.innerHTML = targets.map(t => `
                        <div class="scan-item">
                            <div class="scan-header">
                                <span class="scan-target">${t.host}</span>
                                <button class="btn btn-secondary" onclick="scanTargetById('${t.id}')">Scan</button>
                            </div>
                            <div class="scan-meta">
                                <span>📛 ${t.name}</span>
                                <span>🔍 ${t.scan_count || 0} scans</span>
                            </div>
                        </div>
                    `).join('');
                }
            } catch (e) {}
        }

        async function loadScans() {
            try {
                scans = await api('/scans');
                const active = scans.filter(s => s.status === 'running' || s.status === 'pending');
                
                const renderScan = s => `
                    <div class="scan-item">
                        <div class="scan-header">
                            <span class="scan-target">${s.target_host || '?'}</span>
                            <span class="scan-status ${s.status}">${s.status}</span>
                        </div>
                        <div class="progress-bar"><div class="progress-fill" style="width:${s.progress}%"></div></div>
                        <div class="scan-meta">
                            <span>${s.scan_type}</span>
                            <span>${s.current_tool || '-'}</span>
                            <span>🐛 ${s.finding_count || 0}</span>
                        </div>
                    </div>`;

                document.getElementById('activeScans').innerHTML = active.length ? active.map(renderScan).join('') :
                    '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No active scans</div></div>';
                
                document.getElementById('allScans').innerHTML = scans.length ? scans.map(renderScan).join('') :
                    '<div class="empty-state"><div class="empty-state-icon">🔍</div><div class="empty-state-title">No scans</div></div>';
                
                document.getElementById('statActive').textContent = active.length;
            } catch (e) {}
        }

        async function loadFindings() {
            try {
                findings = await api('/findings');
                const renderFinding = f => `
                    <div class="finding-item">
                        <div class="finding-severity ${f.severity}"></div>
                        <div class="finding-content">
                            <div class="finding-title">${f.title}</div>
                            <div class="finding-meta">${f.severity.toUpperCase()} • ${f.category}</div>
                        </div>
                    </div>`;

                const empty = '<div class="empty-state"><div class="empty-state-icon">🔒</div><div class="empty-state-title">No findings</div></div>';
                
                document.getElementById('recentFindings').innerHTML = findings.length ? findings.slice(0,5).map(renderFinding).join('') : empty;
                document.getElementById('allFindings').innerHTML = findings.length ? findings.map(renderFinding).join('') : empty;
            } catch (e) {}
        }

        async function createTarget() {
            const name = document.getElementById('targetName').value;
            const host = document.getElementById('targetHost').value;
            if (!name || !host) return toast('Fill all fields', 'error');
            try {
                await api('/targets', 'POST', { name, host, description: '', tags: [], scope: [host], out_of_scope: [] });
                toast('Target created', 'success');
                closeModal('newTargetModal');
                loadTargets();
                loadStats();
            } catch (e) { toast(e.message, 'error'); }
        }

        async function startScan() {
            const target_id = document.getElementById('scanTarget').value;
            const scan_type = document.getElementById('scanType').value;
            if (!target_id) return toast('Select target', 'error');
            try {
                const scan = await api('/scans', 'POST', { target_id, scan_type, tools: [], options: {} });
                toast('Scan started', 'success');
                closeModal('newScanModal');
                loadScans();
                addTerminal(`Starting ${scan_type} scan...`, 'output');
                connectWS(scan.id);
            } catch (e) { toast(e.message, 'error'); }
        }

        function scanTargetById(id) {
            document.getElementById('scanTarget').value = id;
            openModal('newScanModal');
        }

        function connectWS(scanId) {
            const ws = new WebSocket(`ws://localhost:8000/ws/scans/${scanId}`);
            ws.onmessage = e => {
                const d = JSON.parse(e.data);
                if (d.type !== 'heartbeat') {
                    addTerminal(`[${d.status}] ${d.message || d.current_tool || ''}`, d.status === 'completed' ? 'success' : 'output');
                    loadScans();
                    loadFindings();
                    loadStats();
                }
            };
        }

        function addTerminal(text, cls = 'output') {
            const t = document.getElementById('terminal');
            t.innerHTML += `<div class="terminal-line"><span class="prompt">$ </span><span class="${cls}">${text}</span></div>`;
            t.scrollTop = t.scrollHeight;
        }

        // Navigation
        document.querySelectorAll('.nav-item[data-page]').forEach(item => {
            item.onclick = () => {
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                item.classList.add('active');
                document.querySelectorAll('[id^="page-"]').forEach(p => p.style.display = 'none');
                document.getElementById('page-' + item.dataset.page).style.display = 'block';
            };
        });

        function openModal(id) { document.getElementById(id).classList.add('active'); }
        function closeModal(id) { document.getElementById(id).classList.remove('active'); }

        function toast(msg, type = 'info') {
            const t = document.createElement('div');
            t.className = 'toast ' + type;
            t.innerHTML = `<span>${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}</span><span>${msg}</span>`;
            document.getElementById('toasts').appendChild(t);
            setTimeout(() => t.remove(), 5000);
        }

        document.querySelectorAll('.modal-overlay').forEach(m => {
            m.onclick = e => { if (e.target === m) m.classList.remove('active'); };
        });

        init();
    </script>
</body>
</html>
'''


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard"""
    html = DASHBOARD_HTML.replace('API_URL_PLACEHOLDER', API_URL)
    return HTMLResponse(content=html)


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "ok", "service": "dashboard", "api_url": API_URL}


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║           KALI-GPT REAL-TIME DASHBOARD v4.1                      ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Dashboard: http://localhost:8080                                ║
║  API:       http://localhost:8000                                ║
║                                                                  ║
║  Make sure the API server is running first:                      ║
║    python3 api_server.py                                         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    print_banner()
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT, log_level="info")
