// ArpSpoofing.jsx
import React, { useState, useEffect, useRef } from "react";
import { Network, Search, Plus, RefreshCw, Play, Square, Maximize2, X, ChartArea, Earth, BrickWallFire, Moon } from "lucide-react";
import { Button } from "../components/ui/button";
import { api, BASE_URL,WS_URL } from "../config/api";
import { io } from "socket.io-client";
import InfoCard from "../components/InfoCard";
import ArpActiveModal from "../components/ArpActiveModal";

const ArpSpoofing = () => {
  const [clientsDevices, setClientsDevices] = useState([]);
  const [devicesInfo, setDevicesInfo] = useState({
    online: null,
    offline: null,
    unreachable: null,
    total: null
  });
  const [devices, setDevices] = useState([]);

  const [expandedDevice, setExpandedDevice] = useState(null);
  const [spoofingDevice, setSpoofingDevice] = useState(null);
  const [terminalLogs, setTerminalLogs] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(false);

  const socketRef = useRef(null);
  const terminalRef = useRef(null);
  const [clientId, setClientId] = useState(() => {
    const existing = localStorage.getItem("client_id");
    if (existing) return existing;
    const generated = `client-${Math.random().toString(36).slice(2)}-${Date.now()}`;
    localStorage.setItem("client_id", generated);
    return generated;
  });
  const [showActiveModal, setShowActiveModal] = useState(false);

  // use clientsDevices if available, otherwise fallback to static devices
  const displayDevices = clientsDevices.length > 0 ? clientsDevices : devices;

  const filteredDevices = displayDevices.filter(
    (device) =>
      device.ip.includes(searchTerm) ||
      (device.hostname || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (device.mac || "").toLowerCase().includes(searchTerm.toLowerCase())
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

  const startArpSpoof = async (device) => {
    // disconnect previous socket
    if (socketRef.current) {
      try { socketRef.current.disconnect(); } catch (e) {}
      socketRef.current = null;
    }

    setTerminalLogs([]);

    // connect to Socket.IO namespace with client_id
    const socket = io(`${WS_URL}/arp-attack`, {
      transports: ["websocket"],
      query: { client_id: clientId },
      autoConnect: true,
    });
    socketRef.current = socket;

    const pushLog = (type, message) => {
      setTerminalLogs((prev) => [
        ...prev,
        { timestamp: new Date().toLocaleTimeString(), type, message },
      ]);
    };

    socket.on("connect", () => {
      pushLog("info", `WS connected as ${clientId}`);
    });
    socket.on("disconnect", () => {
      pushLog("warning", "WS disconnected");
    });
    socket.on("arp_attack", (data) => {
      pushLog("info", data?.status || "ARP attack init");
    });
    socket.on("arp_attack_status", (data) => {
      pushLog("info", data?.summary || JSON.stringify(data));
    });
    socket.on("arp_attack_started", (data) => {
      pushLog("info", data?.message || "ARP attack started");
    });
    socket.on("arp_attack_error", (data) => {
      pushLog("error", data?.error || data?.message || "ARP attack error");
    });
    socket.on("arp_attack_stopping", (data) => {
      pushLog("warning", data?.message || "Stopping ARP attack...");
    });
    socket.on("arp_attack_stopped", (data) => {
      pushLog("info", data?.message || "ARP attack stopped");
      setSpoofingDevice(null);
    });

    try {
      // hit API to start ARP attack
      const response = await api.post(`${BASE_URL}/arp/start`, {
        ip: device.ip,
        client_id: clientId,
      });
      if (response?.data?.status === 1) {
        setSpoofingDevice(device);
        pushLog("info", `Start request accepted for ${device.ip}`);
      } else {
        const msg = response?.data?.message || "Failed to start ARP attack";
        pushLog("error", msg);
        alert(msg);
      }
    } catch (error) {
      console.error("Failed to start ARP attack:", error);
      pushLog("error", error?.message || "Failed to start ARP attack");
      alert("Failed to start ARP attack");
    }
  };

  const stopArpSpoof = async () => {
    try {
      const response = await api.post(`${BASE_URL}/arp/stop`, {
        client_id: clientId,
      });
      if (response?.data?.status === 1) {
        setSpoofingDevice(null);
      } else {
        alert(response?.data?.message || "Failed to stop ARP attack");
      }
    } catch (error) {
      console.error("Failed to stop ARP attack:", error);
      alert("Failed to stop ARP attack");
    } finally {
      if (socketRef.current) {
        try { socketRef.current.disconnect(); } catch (e) {}
        socketRef.current = null;
      }
    }
  };

  const refreshDevices = () => {
    console.log("Refreshing devices...");
    fetchNetworkInfo();
  };

  const addDevice = () => {
    console.log("Adding new device...");
    // open modal / show form
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLogs]);

  // debug: log when devicesInfo or clientsDevices changes
  useEffect(() => {
    console.log("%c[DEVICES_INFO]", "color: cyan", devicesInfo);
  }, [devicesInfo]);

  useEffect(() => {
    console.log("%c[CLIENTS_DEVICES]", "color: lightblue", clientsDevices);
  }, [clientsDevices]);

  useEffect(() => {
    fetchNetworkInfo();

    return () => {
      if (socketRef.current) {
        try { socketRef.current.disconnect(); } catch (e) {}
        socketRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchNetworkInfo = async () => {
    setLoading(true);

    try {
      const clientsResponse = await api.post(BASE_URL+"/traffict/scan-ip", {
        module_name: "icmp",
      });

      if (clientsResponse?.data?.status === 1) {
        const clients = clientsResponse.data.data || [];

        let onlineCount = 0;
        let offlineCount = 0;
        let unreachableCount = 0;

        const detailedClients = await Promise.all(
          clients.map(async (client, index) => {
            try {
              const detailResponse = await api.post(
                BASE_URL+"/info/detail-client",
                { ip: client.ip, mac: client.mac }
              );

              const detail = detailResponse?.data?.data || {};
              const osInfo = detail.os || {};

              let status = "unknown";
              if (osInfo.status === "up") {
                status = "online";
                onlineCount++;
              } else if (osInfo.status === "down") {
                status = "offline";
                offlineCount++;
              } else if (osInfo.status === "uncherable") {
                status = "uncherable";
                unreachableCount++;
              } else {
                unreachableCount++; // treat unknown as unreachable if uncertain
              }

              return {
                ip: client.ip,
                mac: client.mac || "-",
                hostname: detail.hostname || "-",
                vendor: detail.vendor || "Unknown",
                deviceType: detail.deviceType || "Unknown",
                os: osInfo.os || "Unknown",
                status,
                ttl:osInfo.ttl,
                initial_ttl:osInfo.initial_ttl,
                hops:osInfo.hops,
                lastSeen: new Date().toLocaleString(),
              };
            } catch (err) {
              unreachableCount++;
              return {
                ip: client.ip,
                mac: client.mac || "-",
                hostname: "-",
                vendor: "Unknown",
                deviceType: "Unknown",
                os: "Unknown",
                status: "uncherable",
                lastSeen: new Date().toLocaleTimeString(),
              };
            }
          })
        );

        setClientsDevices(detailedClients);
        setDevices(detailedClients);

        const totalCount = onlineCount + offlineCount + unreachableCount;
        const summary = {
          online: onlineCount,
          offline: offlineCount,
          unreachable: unreachableCount,
          total: totalCount,
        };

        setDevicesInfo(summary);
      } else {
        alert(clientsResponse?.data?.message || "Scan failed");
      }
    } catch (error) {
      alert("Failed to fetch network information");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
    <div className="p-8">
      {/* <div>
        <h2>Data Devices Info</h2>
        <pre>{JSON.stringify(clientsDevices, null, 2)}</pre>
      </div> */}

      {/* rest of your UI uses displayDevices / filteredDevices */}
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <InfoCard
          title="Total Devices"
          value={devicesInfo.total}
          subtitle="Total Devices"
          icon={ChartArea}
        />
        <InfoCard
          title="Total Online"
          value={devicesInfo.online}
          subtitle="Device Online"
          icon={Earth}
        />
        <InfoCard
          title="Total Uncherable"
          value={devicesInfo.unreachable}
          subtitle="Device Unchreach"
          icon={BrickWallFire}
        />
        <InfoCard
          title="Total Offline"
          value={devicesInfo.offline}
          subtitle="Device Offline"
          icon={Moon}
        />
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
        <Button
          onClick={() => setShowActiveModal(true)}
          variant="outline"
          className="bg-slate-800/50 border-slate-700/50 hover:bg-slate-700/50"
        >
          <Network className="w-4 h-4 mr-2" />
          Cek Target Aktif
        </Button>
      </div>

      {/* Devices List */}
      <div className="space-y-4">
        {devices.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 text-gray-400 border border-dashed border-gray-700 rounded-2xl bg-[#12141d]/50">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-12 w-12 mb-4 text-gray-600"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <p className="text-lg font-medium">Data tidak ditemukan</p>
            <p className="text-sm text-gray-500 mt-1">
              Coba ubah kata pencarian atau tekan <span className="text-blue-400">Refresh</span>.
            </p>
          </div>
        ):(
        filteredDevices.map((device) => (
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
                        <div className="text-xl">🧭</div>
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
                        <div className="text-xl">🏭</div>
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
                        <div className="text-xl">💻</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            OS
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.os || "-"}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🕐</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            TTL
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.ttl || "-"}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🧮</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            Initial TTL
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.initial_ttl || "-"}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🌐</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            Hops
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.hops || "-"}
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="bg-slate-900/50 border border-slate-700/30 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <div className="text-xl">🏷️</div>
                        <div>
                          <p className="text-xs text-slate-400 mb-1">
                            Hostname
                          </p>
                          <p className="text-sm font-medium text-white">
                            {device.hostname || "-"}
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
        ))
      )}
      </div>
    </div>
    {showActiveModal && (
      <ArpActiveModal
        clientId={clientId}
        onClose={() => setShowActiveModal(false)}
      />
    )}
    </>
  );
};

export default ArpSpoofing;
