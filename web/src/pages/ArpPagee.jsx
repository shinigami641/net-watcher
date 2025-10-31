// ArpSpoofing.jsx
import React, { useState, useEffect, useRef } from "react";
import { Network, Search, Plus, RefreshCw, Play, Square, Maximize2, X } from "lucide-react";
import { Button } from "../components/ui/button";

const ArpSpoofing = () => {
  const [devices, setDevices] = useState([
    {
      ip: "192.168.1.1",
      hostname: "router.local",
      deviceType: "Router",
      status: "online",
      mac: "00:1A:2B:3C:4D:5E",
      vendor: "TP-Link",
      lastSeen: "15 Jan 2025 17:30",
    },
    {
      ip: "192.168.1.10",
      hostname: "desktop-pc",
      deviceType: "PC",
      status: "online",
      mac: "A1:B2:C3:D4:E5:F6",
      vendor: "Intel",
      lastSeen: "15 Jan 2025 17:28",
    },
    {
      ip: "192.168.1.25",
      hostname: "iphone-john",
      deviceType: "Mobile",
      status: "online",
      mac: "11:22:33:44:55:66",
      vendor: "Apple",
      lastSeen: "15 Jan 2025 17:25",
    },
    {
      ip: "192.168.1.50",
      hostname: "unknown-device",
      deviceType: "Unknown",
      status: "offline",
      mac: "FF:EE:DD:CC:BB:AA",
      vendor: "Unknown",
      lastSeen: "15 Jan 2025 16:10",
    },
  ]);

  const [expandedDevice, setExpandedDevice] = useState(null);
  const [spoofingDevice, setSpoofingDevice] = useState(null);
  const [terminalLogs, setTerminalLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const wsRef = useRef(null);
  const terminalRef = useRef(null);

  const stats = {
    total: devices.length,
    online: devices.filter((d) => d.status === "online").length,
    offline: devices.filter((d) => d.status === "offline").length,
  };

  const filteredDevices = devices.filter(
    (device) =>
      device.ip.includes(searchTerm) ||
      device.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.mac.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const toggleExpand = (ip) => {
    setExpandedDevice(expandedDevice === ip ? null : ip);
  };

  const getDeviceIcon = (deviceType) => {
    const icons = {
      Router: "🖧",
      PC: "💻",
      Mobile: "📱",
      Unknown: "❓",
    };
    return icons[deviceType] || "🔌";
  };

  const startArpSpoof = (device) => {
    setSpoofingDevice(device);
    setTerminalLogs([]);

    // Connect to WebSocket
    const ws = new WebSocket("ws://localhost:8080/arp-spoof");
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(
        JSON.stringify({
          action: "start",
          targetIp: device.ip,
          targetMac: device.mac,
        })
      );
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setTerminalLogs((prev) => [
        ...prev,
        {
          timestamp: data.timestamp || new Date().toLocaleTimeString(),
          message: data.message,
          type: data.type || "info",
        },
      ]);
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
      setTerminalLogs((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          message: "WebSocket connection error",
          type: "error",
        },
      ]);
    };

    ws.onclose = () => {
      console.log("WebSocket connection closed");
    };
  };

  const stopArpSpoof = () => {
    if (wsRef.current) {
      wsRef.current.send(JSON.stringify({ action: "stop" }));
      wsRef.current.close();
    }
    setSpoofingDevice(null);
  };

  const refreshDevices = () => {
    console.log("Refreshing devices...");
  };

  const addDevice = () => {
    console.log("Adding new device...");
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLogs]);

  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-blue-700 rounded-xl flex items-center justify-center">
            <Network className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Network Manager</h1>
            <p className="text-slate-400">
              Kelola dan monitor perangkat di jaringan Anda
            </p>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
          <div className="flex items-center gap-3">
            <div className="text-2xl">📊</div>
            <div>
              <p className="text-sm text-slate-400 mb-1">Total Perangkat</p>
              <p className="text-3xl font-bold text-white">{stats.total}</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
            </div>
            <div>
              <p className="text-sm text-slate-400 mb-1">Online</p>
              <p className="text-3xl font-bold text-white">{stats.online}</p>
            </div>
          </div>
        </div>
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
            </div>
            <div>
              <p className="text-sm text-slate-400 mb-1">Offline</p>
              <p className="text-3xl font-bold text-white">{stats.offline}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex gap-3 mb-6">
        <div className="flex-1 relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
          <input
            type="text"
            placeholder="Cari IP, hostname, atau MAC address..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-800/50 border border-slate-700/50 rounded-lg pl-12 pr-4 py-3 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50"
          />
        </div>
        <Button
          onClick={refreshDevices}
          variant="outline"
          className="bg-slate-800/50 border-slate-700/50 hover:bg-slate-700/50"
        >
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
        <Button onClick={addDevice}>
          <Plus className="w-4 h-4 mr-2" />
          Tambah IP
        </Button>
      </div>

      {/* Devices List */}
      <div className="space-y-4">
        {filteredDevices.map((device) => (
          <div
            key={device.ip}
            className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden hover:border-slate-600/50 transition-colors"
          >
            {/* Device Header */}
            <div
              className="p-5 cursor-pointer"
              onClick={() => toggleExpand(device.ip)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-center justify-center text-2xl">
                    {getDeviceIcon(device.deviceType)}
                  </div>
                  <div>
                    <div className="flex items-center gap-3 mb-1">
                      <span className="text-lg font-semibold text-white">
                        {device.ip}
                      </span>
                      <span
                        className={`px-3 py-1 rounded-full text-xs font-medium ${
                          device.status === "online"
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                            : "bg-red-500/20 text-red-400 border border-red-500/30"
                        }`}
                      >
                        {device.status}
                      </span>
                    </div>
                    <p className="text-sm text-slate-400">
                      {device.hostname} • {device.deviceType}
                    </p>
                  </div>
                </div>
                <button className="text-slate-400 hover:text-slate-300 transition-colors">
                  <svg
                    className={`w-5 h-5 transition-transform ${
                      expandedDevice === device.ip ? "rotate-180" : ""
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </button>
              </div>
            </div>

            {/* Expanded Content */}
            {expandedDevice === device.ip && (
              <div className="px-5 pb-5 border-t border-slate-700/50">
                <div className="pt-5 space-y-4">
                  {/* Device Info Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🔧</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            MAC Address
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.mac}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🏢</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">Vendor</p>
                          <p className="text-sm font-medium text-white">
                            {device.vendor}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🕐</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            Last Seen
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.lastSeen}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex justify-end pt-2">
                    {/* ARP Spoof Button */}
                    {spoofingDevice?.ip === device.ip ? (
                        <Button
                        onClick={stopArpSpoof}
                        className="inline-flex items-center w-auto bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800"
                        >
                        <Square className="w-4 h-4 mr-2" />
                        Stop ARP Spoof
                        </Button>
                    ) : (
                        <Button
                        onClick={() => startArpSpoof(device)}
                        disabled={device.status === "offline"}
                        className="inline-flex items-center w-auto bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-700 hover:to-emerald-800 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                        <Play className="w-4 h-4 mr-2" />
                        Start ARP Spoof
                        </Button>
                    )}    
                  </div>

                  {/* Terminal */}
                  {spoofingDevice?.ip === device.ip && (
                    <div className="bg-black border border-slate-700/50 rounded-lg overflow-hidden">
                      {/* Terminal Header */}
                      <div className="bg-slate-800/80 border-b border-slate-700/50 px-4 py-3 flex items-center justify-between">
                        <span className="text-sm text-slate-400 font-mono">
                          root@kali:~# ARP Spoofing Terminal
                        </span>
                        <div className="flex items-center gap-2">
                          <button className="text-slate-400 hover:text-slate-300 transition-colors">
                            <Maximize2 className="w-4 h-4" />
                          </button>
                          <button className="text-slate-400 hover:text-slate-300 transition-colors">
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      </div>

                      {/* Terminal Content */}
                      <div
                        ref={terminalRef}
                        className="p-4 font-mono text-sm max-h-80 overflow-y-auto"
                      >
                        {terminalLogs.map((log, index) => (
                          <div key={index} className="mb-1 flex gap-2">
                            <span className="text-slate-500">
                              {log.timestamp}
                            </span>
                            <span
                              className={`font-medium ${
                                log.type === "error"
                                  ? "text-red-400"
                                  : log.type === "warning"
                                  ? "text-yellow-400"
                                  : "text-emerald-400"
                              }`}
                            >
                              [{log.type}]
                            </span>
                            <span className="text-slate-200">{log.message}</span>
                          </div>
                        ))}
                        <div className="flex items-center">
                          <span className="text-emerald-400 animate-pulse">
                            ▋
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default ArpSpoofing;