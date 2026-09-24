/**
 * Linux SSH Security Monitor - Web Application & Interactive NOC Console
 * Displays the real-time monitoring interface, rule simulator, terminal diagnostics,
 * and deployment files.
 */

import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  Server,
  Activity,
  CheckCircle2,
  Terminal,
  FileCode,
  Play,
  RotateCcw,
  Search,
  Filter,
  Eye,
  Lock,
  Zap,
  Globe,
  Radio,
  Check,
  Copy,
} from "lucide-react";

interface SSHEvent {
  id: number;
  timestamp: string;
  eventType:
    | "AUTH_FAILURE"
    | "AUTH_SUCCESS_PASSWORD"
    | "AUTH_SUCCESS_PUBLICKEY"
    | "INVALID_USER"
    | "SESSION_OPEN"
    | "SESSION_CLOSE"
    | "DISCONNECT"
    | "UNKNOWN_SSH_EVENT";
  username: string | null;
  sourceIp: string | null;
  sourcePort: number | null;
  service: string;
  hostname: string;
  rawMessage: string;
  parserConfidence: "HIGH" | "MEDIUM" | "LOW";
}

interface AlertItem {
  id: number;
  timestamp: string;
  ruleId: string;
  alertType: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  sourceIp: string | null;
  username: string | null;
  description: string;
  evidence: Record<string, any>;
  status: "active" | "acknowledged" | "resolved";
}

const INITIAL_EVENTS: SSHEvent[] = [
  {
    id: 101,
    timestamp: new Date(Date.now() - 340000).toISOString(),
    eventType: "AUTH_FAILURE",
    username: "admin",
    sourceIp: "192.168.1.10",
    sourcePort: 42132,
    service: "sshd",
    hostname: "debian-srv01",
    rawMessage: "Failed password for invalid user admin from 192.168.1.10 port 42132 ssh2",
    parserConfidence: "HIGH",
  },
  {
    id: 102,
    timestamp: new Date(Date.now() - 280000).toISOString(),
    eventType: "AUTH_FAILURE",
    username: "root",
    sourceIp: "192.168.1.10",
    sourcePort: 42134,
    service: "sshd",
    hostname: "debian-srv01",
    rawMessage: "Failed password for root from 192.168.1.10 port 42134 ssh2",
    parserConfidence: "HIGH",
  },
  {
    id: 103,
    timestamp: new Date(Date.now() - 220000).toISOString(),
    eventType: "AUTH_FAILURE",
    username: "ubuntu",
    sourceIp: "192.168.1.10",
    sourcePort: 42136,
    service: "sshd",
    hostname: "debian-srv01",
    rawMessage: "Failed password for invalid user ubuntu from 192.168.1.10 port 42136 ssh2",
    parserConfidence: "HIGH",
  },
  {
    id: 104,
    timestamp: new Date(Date.now() - 160000).toISOString(),
    eventType: "AUTH_SUCCESS_PUBLICKEY",
    username: "vishnu",
    sourceIp: "10.0.0.45",
    sourcePort: 55412,
    service: "sshd",
    hostname: "debian-srv01",
    rawMessage: "Accepted publickey for vishnu from 10.0.0.45 port 55412 ssh2: RSA SHA256:4a3b2c1d",
    parserConfidence: "HIGH",
  },
  {
    id: 105,
    timestamp: new Date(Date.now() - 100000).toISOString(),
    eventType: "SESSION_OPEN",
    username: "vishnu",
    sourceIp: null,
    sourcePort: null,
    service: "sshd",
    hostname: "debian-srv01",
    rawMessage: "pam_unix(sshd:session): session opened for user vishnu by (uid=0)",
    parserConfidence: "HIGH",
  },
  {
    id: 106,
    timestamp: new Date(Date.now() - 60000).toISOString(),
    eventType: "AUTH_FAILURE",
    username: "deploy",
    sourceIp: "2001:db8::1",
    sourcePort: 38921,
    service: "sshd",
    hostname: "debian-srv01",
    rawMessage: "Failed password for deploy from 2001:db8::1 port 38921 ssh2",
    parserConfidence: "HIGH",
  },
];

const INITIAL_ALERTS: AlertItem[] = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 220000).toISOString(),
    ruleId: "RULE-002",
    alertType: "USERNAME_ENUMERATION",
    severity: "HIGH",
    sourceIp: "192.168.1.10",
    username: "ubuntu",
    description: "Username enumeration detected from 192.168.1.10: tried 3 usernames within 180s.",
    evidence: {
      distinct_users: ["admin", "root", "ubuntu"],
      window_seconds: 180,
    },
    status: "active",
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<"dashboard" | "simulator" | "cli" | "codebase">("dashboard");
  const [events, setEvents] = useState<SSHEvent[]>(INITIAL_EVENTS);
  const [alerts, setAlerts] = useState<AlertItem[]>(INITIAL_ALERTS);
  const [filterSeverity, setFilterSeverity] = useState<string>("");
  const [filterType, setFilterType] = useState<string>("");
  const [searchIp, setSearchIp] = useState<string>("");
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<string>("");

  // CLI state
  const [cliInput, setCliInput] = useState<string>("ssh-monitor status");
  const [cliHistory, setCliHistory] = useState<Array<{ cmd: string; output: string }>>([
    {
      cmd: "ssh-monitor health",
      output:
        "[✓] SQLite Database: OK (PRAGMA WAL mode active)\n[✓] systemd-journald: Available via journalctl\n[✓] SSH Service Unit: Detected as sshd\n[✓] Supplementary Groups: systemd-journal verified\nOverall System Health: OK",
    },
  ]);

  // Handle Acknowledge Alert
  const handleAcknowledge = (id: number) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === id ? { ...a, status: "acknowledged" } : a))
    );
  };

  // Run attack simulation scenario
  const triggerScenario = (scenarioType: string) => {
    const now = new Date().toISOString();
    let newEvs: SSHEvent[] = [];
    let newAlerts: AlertItem[] = [];

    if (scenarioType === "bruteforce") {
      const ip = "198.51.100.99";
      for (let i = 1; i <= 5; i++) {
        newEvs.push({
          id: Date.now() + i,
          timestamp: now,
          eventType: "AUTH_FAILURE",
          username: "admin",
          sourceIp: ip,
          sourcePort: 40000 + i,
          service: "sshd",
          hostname: "debian-srv01",
          rawMessage: `Failed password for invalid user admin from ${ip} port ${40000 + i} ssh2`,
          parserConfidence: "HIGH",
        });
      }
      newAlerts.push({
        id: Date.now() + 10,
        timestamp: now,
        ruleId: "RULE-001",
        alertType: "SSH_BRUTE_FORCE",
        severity: "HIGH",
        sourceIp: ip,
        username: "admin",
        description: `Potential SSH brute-force attack from ${ip}: 5 failed attempts within 120s.`,
        evidence: { attempt_count: 5, window_seconds: 120, threshold: 5 },
        status: "active",
      });
    } else if (scenarioType === "root_login") {
      const ip = "203.0.113.88";
      newEvs.push({
        id: Date.now(),
        timestamp: now,
        eventType: "AUTH_SUCCESS_PUBLICKEY",
        username: "root",
        sourceIp: ip,
        sourcePort: 51234,
        service: "sshd",
        hostname: "debian-srv01",
        rawMessage: `Accepted publickey for root from ${ip} port 51234 ssh2: RSA SHA256:rootKeyHash`,
        parserConfidence: "HIGH",
      });
      newAlerts.push({
        id: Date.now() + 1,
        timestamp: now,
        ruleId: "RULE-004",
        alertType: "ROOT_LOGIN",
        severity: "MEDIUM",
        sourceIp: ip,
        username: "root",
        description: `Privileged root SSH login accepted from ${ip} via AUTH_SUCCESS_PUBLICKEY.`,
        evidence: { auth_method: "AUTH_SUCCESS_PUBLICKEY", source_ip: ip },
        status: "active",
      });
    } else if (scenarioType === "success_after_failure") {
      const ip = "192.0.2.77";
      for (let i = 1; i <= 3; i++) {
        newEvs.push({
          id: Date.now() + i,
          timestamp: now,
          eventType: "AUTH_FAILURE",
          username: "target_user",
          sourceIp: ip,
          sourcePort: 45000 + i,
          service: "sshd",
          hostname: "debian-srv01",
          rawMessage: `Failed password for target_user from ${ip} port ${45000 + i} ssh2`,
          parserConfidence: "HIGH",
        });
      }
      newEvs.push({
        id: Date.now() + 4,
        timestamp: now,
        eventType: "AUTH_SUCCESS_PASSWORD",
        username: "target_user",
        sourceIp: ip,
        sourcePort: 45005,
        service: "sshd",
        hostname: "debian-srv01",
        rawMessage: `Accepted password for target_user from ${ip} port 45005 ssh2`,
        parserConfidence: "HIGH",
      });
      newAlerts.push({
        id: Date.now() + 12,
        timestamp: now,
        ruleId: "RULE-003",
        alertType: "SUSPICIOUS_AUTH_SUCCESS",
        severity: "CRITICAL",
        sourceIp: ip,
        username: "target_user",
        description: `Suspicious authentication activity: Successful login for user 'target_user' from ${ip} immediately following 3 failed attempts.`,
        evidence: { prior_failure_count: 3, window_seconds: 300 },
        status: "active",
      });
    } else if (scenarioType === "failure_burst") {
      for (let i = 1; i <= 15; i++) {
        newEvs.push({
          id: Date.now() + i,
          timestamp: now,
          eventType: "AUTH_FAILURE",
          username: `bot_${i}`,
          sourceIp: `185.220.101.${i}`,
          sourcePort: 30000 + i,
          service: "sshd",
          hostname: "debian-srv01",
          rawMessage: `Failed password for invalid user bot_${i} from 185.220.101.${i} port ${30000 + i} ssh2`,
          parserConfidence: "HIGH",
        });
      }
      newAlerts.push({
        id: Date.now() + 20,
        timestamp: now,
        ruleId: "RULE-006",
        alertType: "AUTH_FAILURE_BURST",
        severity: "CRITICAL",
        sourceIp: "185.220.101.1",
        username: "distributed_botnet",
        description:
          "System-wide authentication failure burst: 15 failures across 15 source IPs within 60s.",
        evidence: { failure_count: 15, window_seconds: 60, distinct_source_count: 15 },
        status: "active",
      });
    }

    setEvents((prev) => [...newEvs, ...prev]);
    setAlerts((prev) => [...newAlerts, ...prev]);
  };

  // Run simulated CLI command
  const handleExecuteCli = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = cliInput.trim();
    if (!cmd) return;

    let output = "";
    if (cmd === "ssh-monitor health") {
      output =
        "[✓] SQLite Database: OK (PRAGMA WAL mode active)\n[✓] systemd-journald: Available (/bin/journalctl)\n[✓] SSH Service Unit: sshd.service active\n[✓] User Privileges: user 'sshmon' in 'systemd-journal' group\nOverall System Health: OK";
    } else if (cmd === "ssh-monitor status") {
      output = `Component / Metric          Status / Value
────────────────────────────────────────────
Version                     1.0.0
Hostname                    debian-srv01
Database                    sqlite:///./data/ssh_monitor.db
Total Events Recorded       ${events.length}
Total Alerts Triggered      ${alerts.length}
Active Alerts               ${alerts.filter((a) => a.status === "active").length}
Target Service              sshd (systemd journal stream)`;
    } else if (cmd === "ssh-monitor test-parser") {
      output = `SSH Parser Extraction Results
Event Type              User         Source IP        Port    Confidence
──────────────────────────────────────────────────────────────────────────
AUTH_FAILURE            admin        192.168.1.10     42132   HIGH
AUTH_FAILURE            vishnu       10.0.0.5         51234   HIGH
AUTH_SUCCESS_PASSWORD   vishnu       192.168.1.50     55412   HIGH
AUTH_SUCCESS_PUBLICKEY  deploy       2001:db8::1      34567   HIGH
INVALID_USER            test         192.168.1.99     60001   HIGH
DISCONNECT              hacker       185.220.101.5    44321   HIGH`;
    } else if (cmd === "ssh-monitor test-detection") {
      output = `Simulating SSH Attack Scenarios through Detection Engine...
▶ Scenario 1: Brute Force (5 rapid failures)
  ALERT TRIGGERED: [HIGH] SSH_BRUTE_FORCE - Potential SSH brute-force attack from 192.0.2.1: 5 failures.
▶ Scenario 2: Success following 3 failures
  ALERT TRIGGERED: [CRITICAL] SUSPICIOUS_AUTH_SUCCESS - Suspicious authentication activity: Successful login following 3 failures.
▶ Scenario 3: Privileged Root Login
  ALERT TRIGGERED: [MEDIUM] ROOT_LOGIN - Privileged root SSH login accepted from 203.0.113.88.`;
    } else if (cmd === "ssh-monitor events") {
      output = events
        .slice(0, 5)
        .map(
          (ev) =>
            `[${ev.id}] ${ev.timestamp.substring(11, 19)} | ${ev.eventType} | ${ev.username || "-"} | ${ev.sourceIp || "-"}`
        )
        .join("\n");
    } else if (cmd === "ssh-monitor alerts") {
      output = alerts
        .map(
          (al) =>
            `[${al.id}] [${al.severity}] ${al.alertType} | Source: ${al.sourceIp || "-"} | Status: ${al.status}`
        )
        .join("\n");
    } else if (cmd === "ssh-monitor cleanup") {
      output = "Retention cleanup completed: Pruned 0 historical records beyond retention window.";
    } else if (cmd === "ssh-monitor version") {
      output = "SSH Security Monitor v1.0.0 (Python 3.12, FastAPI, SQLAlchemy 2.0, SQLite WAL)";
    } else {
      output = `Command not recognized: ${cmd}\nAvailable: health, status, test-parser, test-detection, events, alerts, cleanup, version`;
    }

    setCliHistory((prev) => [...prev, { cmd, output }]);
    setCliInput("");
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(""), 2000);
  };

  // Metrics computation
  const totalEvents = events.length;
  const failedAuths = events.filter(
    (e) => e.eventType === "AUTH_FAILURE" || e.eventType === "INVALID_USER"
  ).length;
  const successAuths = events.filter((e) =>
    e.eventType.startsWith("AUTH_SUCCESS")
  ).length;
  const activeAlerts = alerts.filter((a) => a.status === "active").length;
  const uniqueIps = new Set(events.map((e) => e.sourceIp).filter(Boolean)).size;

  // Filtered lists
  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity && a.severity !== filterSeverity) return false;
    return true;
  });

  const filteredEvents = events.filter((e) => {
    if (filterType && e.eventType !== filterType) return false;
    if (searchIp && e.sourceIp && !e.sourceIp.includes(searchIp)) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Header */}
      <header className="border-b border-slate-800 bg-[#0c1220]/90 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-wider text-white text-base">
                SSH SECURITY MONITOR
              </span>
              <span className="text-[10px] uppercase font-bold tracking-widest px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                v1.0.0
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-1.5">
              <span>HOST: debian-srv01</span>
              <span>•</span>
              <span className="text-emerald-400 font-mono">systemd-journald follow</span>
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center bg-slate-900/90 p-1 rounded-lg border border-slate-800 text-xs font-semibold">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`px-3.5 py-1.5 rounded-md transition flex items-center gap-2 ${
              activeTab === "dashboard"
                ? "bg-cyan-500 text-black shadow font-bold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            NOC Dashboard
          </button>
          <button
            onClick={() => setActiveTab("simulator")}
            className={`px-3.5 py-1.5 rounded-md transition flex items-center gap-2 ${
              activeTab === "simulator"
                ? "bg-cyan-500 text-black shadow font-bold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            Attack Simulator
          </button>
          <button
            onClick={() => setActiveTab("cli")}
            className={`px-3.5 py-1.5 rounded-md transition flex items-center gap-2 ${
              activeTab === "cli"
                ? "bg-cyan-500 text-black shadow font-bold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            CLI Diagnostics
          </button>
          <button
            onClick={() => setActiveTab("codebase")}
            className={`px-3.5 py-1.5 rounded-md transition flex items-center gap-2 ${
              activeTab === "codebase"
                ? "bg-cyan-500 text-black shadow font-bold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            Deploy & Source
          </button>
        </div>

        {/* Live Status indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
            <span className="font-mono text-emerald-400 font-bold">WS CONNECTED</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Metric Cards Row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-[#0e1524] border border-slate-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Total SSH Events</div>
            <div className="text-2xl font-black text-white mt-1">{totalEvents.toLocaleString()}</div>
            <div className="text-[11px] text-slate-500 mt-1">SQLite WAL journal</div>
            <div className="absolute top-0 left-0 w-1 h-full bg-cyan-500" />
          </div>

          <div className="bg-[#0e1524] border border-slate-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Failed Logins</div>
            <div className="text-2xl font-black text-rose-400 mt-1">{failedAuths.toLocaleString()}</div>
            <div className="text-[11px] text-slate-500 mt-1">Auth drops & invalid users</div>
            <div className="absolute top-0 left-0 w-1 h-full bg-rose-500" />
          </div>

          <div className="bg-[#0e1524] border border-slate-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Successful Logins</div>
            <div className="text-2xl font-black text-emerald-400 mt-1">{successAuths.toLocaleString()}</div>
            <div className="text-[11px] text-slate-500 mt-1">Password & Publickey</div>
            <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500" />
          </div>

          <div className="bg-[#0e1524] border border-slate-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Active Alerts</div>
            <div className={`text-2xl font-black mt-1 ${activeAlerts > 0 ? "text-amber-400 animate-pulse" : "text-slate-400"}`}>
              {activeAlerts}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Pending investigation</div>
            <div className="absolute top-0 left-0 w-1 h-full bg-amber-500" />
          </div>

          <div className="bg-[#0e1524] border border-slate-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Unique Source IPs</div>
            <div className="text-2xl font-black text-purple-400 mt-1">{uniqueIps}</div>
            <div className="text-[11px] text-slate-500 mt-1">Known remote hosts</div>
            <div className="absolute top-0 left-0 w-1 h-full bg-purple-500" />
          </div>
        </div>

        {/* TAB 1: NOC DASHBOARD */}
        {activeTab === "dashboard" && (
          <div className="space-y-6">
            {/* Real-time Alerts Panel */}
            <div className="bg-[#0e1524] border border-slate-800 rounded-xl shadow-lg overflow-hidden">
              <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-[#11192a]">
                <div className="flex items-center gap-2.5">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <h2 className="text-sm font-bold tracking-wide uppercase text-white">
                    Detection Engine Alerts
                  </h2>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    REAL-TIME STREAM
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="bg-slate-900 border border-slate-700 text-slate-200 px-2.5 py-1 rounded text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 font-semibold bg-[#0b101c]">
                      <th className="p-3">Time (UTC)</th>
                      <th className="p-3">Rule ID</th>
                      <th className="p-3">Alert Type</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Source IP</th>
                      <th className="p-3">User</th>
                      <th className="p-3">Description</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredAlerts.length === 0 ? (
                      <tr>
                        <td colSpan={9} className="p-6 text-center text-slate-500">
                          No alerts matching selected criteria.
                        </td>
                      </tr>
                    ) : (
                      filteredAlerts.map((a) => (
                        <tr key={a.id} className="hover:bg-slate-800/30 transition">
                          <td className="p-3 font-mono text-slate-400">
                            {a.timestamp.substring(11, 19)}
                          </td>
                          <td className="p-3 font-mono font-bold text-cyan-400">{a.ruleId}</td>
                          <td className="p-3 font-bold text-white">{a.alertType}</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-extrabold ${
                                a.severity === "CRITICAL"
                                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                                  : a.severity === "HIGH"
                                  ? "bg-orange-500/20 text-orange-400 border border-orange-500/40"
                                  : a.severity === "MEDIUM"
                                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                                  : "bg-blue-500/20 text-blue-400 border border-blue-500/40"
                              }`}
                            >
                              {a.severity}
                            </span>
                          </td>
                          <td className="p-3 font-mono text-cyan-300">{a.sourceIp || "-"}</td>
                          <td className="p-3 font-medium text-purple-300">{a.username || "-"}</td>
                          <td className="p-3 max-w-xs truncate text-slate-300" title={a.description}>
                            {a.description}
                          </td>
                          <td className="p-3">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                a.status === "active"
                                  ? "bg-rose-900/30 text-rose-300"
                                  : a.status === "acknowledged"
                                  ? "bg-amber-900/30 text-amber-300"
                                  : "bg-emerald-900/30 text-emerald-300"
                              }`}
                            >
                              {a.status}
                            </span>
                          </td>
                          <td className="p-3">
                            {a.status === "active" ? (
                              <button
                                onClick={() => handleAcknowledge(a.id)}
                                className="px-2 py-1 bg-amber-500/20 text-amber-300 hover:bg-amber-500 hover:text-black rounded border border-amber-500/30 transition text-[11px] font-bold"
                              >
                                Acknowledge
                              </button>
                            ) : (
                              <span className="text-slate-500 text-[11px] flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                Acked
                              </span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Normalized Events Feed */}
            <div className="bg-[#0e1524] border border-slate-800 rounded-xl shadow-lg overflow-hidden">
              <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-[#11192a]">
                <div className="flex items-center gap-2.5">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-sm font-bold tracking-wide uppercase text-white">
                    Normalized SSH Journal Events
                  </h2>
                  <span className="text-[11px] text-slate-400 font-mono">
                    ({filteredEvents.length} items)
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-500" />
                    <input
                      type="text"
                      placeholder="Filter by IP..."
                      value={searchIp}
                      onChange={(e) => setSearchIp(e.target.value)}
                      className="bg-slate-900 border border-slate-700 text-slate-200 pl-8 pr-2.5 py-1 rounded text-xs focus:outline-none focus:border-cyan-500 w-36"
                    />
                  </div>
                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    className="bg-slate-900 border border-slate-700 text-slate-200 px-2.5 py-1 rounded text-xs focus:outline-none focus:border-cyan-500"
                  >
                    <option value="">All Event Types</option>
                    <option value="AUTH_FAILURE">AUTH_FAILURE</option>
                    <option value="AUTH_SUCCESS_PASSWORD">AUTH_SUCCESS_PASSWORD</option>
                    <option value="AUTH_SUCCESS_PUBLICKEY">AUTH_SUCCESS_PUBLICKEY</option>
                    <option value="INVALID_USER">INVALID_USER</option>
                    <option value="SESSION_OPEN">SESSION_OPEN</option>
                    <option value="DISCONNECT">DISCONNECT</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto max-h-96">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="sticky top-0 bg-[#0b101c] z-10">
                    <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                      <th className="p-3">Time (UTC)</th>
                      <th className="p-3">Event Type</th>
                      <th className="p-3">User</th>
                      <th className="p-3">Source IP</th>
                      <th className="p-3">Port</th>
                      <th className="p-3">Raw Journald Message</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredEvents.map((ev) => (
                      <tr key={ev.id} className="hover:bg-slate-800/30 transition">
                        <td className="p-3 text-slate-400">{ev.timestamp.substring(11, 19)}</td>
                        <td className="p-3 font-sans">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              ev.eventType.includes("FAILURE") || ev.eventType.includes("INVALID")
                                ? "bg-rose-500/20 text-rose-400"
                                : ev.eventType.includes("SUCCESS")
                                ? "bg-emerald-500/20 text-emerald-400"
                                : "bg-cyan-500/20 text-cyan-400"
                            }`}
                          >
                            {ev.eventType}
                          </span>
                        </td>
                        <td className="p-3 font-sans font-semibold text-purple-300">
                          {ev.username || "-"}
                        </td>
                        <td className="p-3 text-cyan-300">{ev.sourceIp || "-"}</td>
                        <td className="p-3 text-slate-400">{ev.sourcePort || "-"}</td>
                        <td
                          className="p-3 text-slate-400 text-[11px] max-w-md truncate"
                          title={ev.rawMessage}
                        >
                          {ev.rawMessage}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: ATTACK SIMULATOR */}
        {activeTab === "simulator" && (
          <div className="bg-[#0e1524] border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Zap className="w-5 h-5 text-cyan-400" />
                Detection Engine Live Rule Verification
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Inject synthetic OpenSSH attack vectors into the pipeline to verify RULE-001 through RULE-006 trigger conditions in real-time.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-400 font-mono">RULE-001</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 font-bold">
                      HIGH
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-1">SSH Brute-Force Candidate</h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Simulates 5 consecutive rapid authentication failures from IP <code>198.51.100.99</code> targeting user 'admin'.
                  </p>
                </div>
                <button
                  onClick={() => triggerScenario("bruteforce")}
                  className="mt-4 px-3 py-2 bg-gradient-to-r from-orange-500 to-amber-600 hover:opacity-90 text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 shadow"
                >
                  <Play className="w-3.5 h-3.5" />
                  Simulate Brute Force Attack
                </button>
              </div>

              <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-400 font-mono">RULE-003</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                      CRITICAL
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-1">
                    Success Following Repeated Failures
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Simulates 3 failed password attempts followed immediately by an accepted login from <code>192.0.2.77</code>.
                  </p>
                </div>
                <button
                  onClick={() => triggerScenario("success_after_failure")}
                  className="mt-4 px-3 py-2 bg-gradient-to-r from-rose-500 to-red-600 hover:opacity-90 text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 shadow"
                >
                  <Play className="w-3.5 h-3.5" />
                  Simulate Password Guessing Success
                </button>
              </div>

              <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-400 font-mono">RULE-004</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold">
                      MEDIUM
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-1">Privileged Root Login</h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Simulates successful public key authentication directly for superuser <code>root</code> from <code>203.0.113.88</code>.
                  </p>
                </div>
                <button
                  onClick={() => triggerScenario("root_login")}
                  className="mt-4 px-3 py-2 bg-gradient-to-r from-amber-500 to-yellow-600 hover:opacity-90 text-black rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 shadow"
                >
                  <Play className="w-3.5 h-3.5" />
                  Simulate Root Publickey Login
                </button>
              </div>

              <div className="border border-slate-800 bg-slate-900/60 rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-400 font-mono">RULE-006</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                      CRITICAL
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-1">
                    System-Wide Failure Burst (Botnet)
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Simulates 15 authentication drops across 15 distinct distributed botnet IPs in under 60 seconds.
                  </p>
                </div>
                <button
                  onClick={() => triggerScenario("failure_burst")}
                  className="mt-4 px-3 py-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:opacity-90 text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 shadow"
                >
                  <Play className="w-3.5 h-3.5" />
                  Simulate Distributed Botnet Burst
                </button>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: CLI TERMINAL */}
        {activeTab === "cli" && (
          <div className="bg-[#0b0f19] border border-slate-800 rounded-xl shadow-xl overflow-hidden font-mono">
            <div className="bg-slate-900 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>root@debian-srv01:~# /usr/local/bin/ssh-monitor</span>
              </div>
              <span className="text-[11px] text-slate-500">Interactive Linux CLI Session</span>
            </div>

            <div className="p-4 space-y-4 max-h-[500px] overflow-y-auto text-xs">
              <div className="text-slate-500">
                # Linux SSH Security Monitor CLI Console Simulator
                <br /># Try typing: health, status, test-parser, test-detection, events, alerts, cleanup, version
              </div>

              {cliHistory.map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="text-cyan-400 flex items-center gap-1.5">
                    <span className="text-emerald-400">sshmon@debian:~$</span>
                    <span>{item.cmd}</span>
                  </div>
                  <pre className="text-slate-300 bg-black/40 p-3 rounded-lg border border-slate-800/80 whitespace-pre-wrap leading-relaxed">
                    {item.output}
                  </pre>
                </div>
              ))}

              <form onSubmit={handleExecuteCli} className="flex items-center gap-2 pt-2">
                <span className="text-emerald-400">sshmon@debian:~$</span>
                <input
                  type="text"
                  value={cliInput}
                  onChange={(e) => setCliInput(e.target.value)}
                  placeholder="ssh-monitor status"
                  className="flex-1 bg-transparent border-none text-cyan-300 focus:outline-none text-xs font-mono"
                  autoFocus
                />
                <button
                  type="submit"
                  className="px-2.5 py-1 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded text-xs hover:bg-cyan-500 hover:text-black transition"
                >
                  Execute
                </button>
              </form>
            </div>
          </div>
        )}

        {/* TAB 4: DEPLOY & SOURCE CODE */}
        {activeTab === "codebase" && (
          <div className="bg-[#0e1524] border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                Production Deployment & Configuration
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Commands and service files ready to run on any fresh Debian 12 or Ubuntu 22.04/24.04 Server.
              </p>
            </div>

            {/* Quick 1-line install */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Debian / Ubuntu Production Quick Install
                </span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      "git clone https://github.com/security/ssh-security-monitor.git && cd ssh-security-monitor && sudo ./scripts/install.sh",
                      "install_cmd"
                    )
                  }
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  {copiedKey === "install_cmd" ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy Command
                    </>
                  )}
                </button>
              </div>
              <pre className="mt-2 text-xs font-mono text-emerald-400 bg-black/60 p-3 rounded border border-slate-800 overflow-x-auto">
                git clone https://github.com/security/ssh-security-monitor.git
                <br />
                cd ssh-security-monitor
                <br />
                sudo ./scripts/install.sh
              </pre>
            </div>

            {/* Systemd Service Unit */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  systemd/ssh-security-monitor.service (Hardened Security Sandbox)
                </span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      `[Unit]
Description=SSH Security Monitor Daemon & Web Dashboard
After=network.target systemd-journald.service ssh.service sshd.service
Wants=systemd-journald.service

[Service]
Type=simple
User=sshmon
Group=sshmon
SupplementaryGroups=systemd-journal adm
WorkingDirectory=/opt/ssh-security-monitor
EnvironmentFile=-/etc/ssh-security-monitor/ssh-security-monitor.env
ExecStart=/opt/ssh-security-monitor/.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true`,
                      "systemd"
                    )
                  }
                  className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  {copiedKey === "systemd" ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy Unit File
                    </>
                  )}
                </button>
              </div>
              <pre className="mt-2 text-xs font-mono text-slate-300 bg-black/60 p-3 rounded border border-slate-800 overflow-x-auto max-h-48">
{`[Unit]
Description=SSH Security Monitor Daemon & Web Dashboard
After=network.target systemd-journald.service ssh.service sshd.service
Wants=systemd-journald.service

[Service]
Type=simple
User=sshmon
Group=sshmon
SupplementaryGroups=systemd-journal adm
WorkingDirectory=/opt/ssh-security-monitor
EnvironmentFile=-/etc/ssh-security-monitor/ssh-security-monitor.env
ExecStart=/opt/ssh-security-monitor/.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true`}
              </pre>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#0a0e18] px-6 py-4 text-center text-xs text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Linux SSH Security Monitor • Production Architecture</span>
        </div>
        <div>
          <span>SQLite WAL • systemd-journald • FastAPI • WebSocket • Linux Hardened</span>
        </div>
      </footer>
    </div>
  );
}
