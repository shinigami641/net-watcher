import React, { useEffect, useState, useRef } from "react";
import { X, Activity, Play, Square } from "lucide-react";
import { Button } from "./ui/button";
import { api, API_ENDPOINTS, WS_URL } from "../config/api";
import { io } from "socket.io-client";

const TrafficModal = ({ clientIp, onClose }) => {
  const [trafficData, setTrafficData] = useState([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [clientId, setClientId] = useState(null);
  const [socket, setSocket] = useState(null);
  const [status, setStatus] = useState("Ready to start monitoring");
  const [isStopping, setIsStopping] = useState(false);
  const [isStarting, setIsStarting] = useState(false);
  const tableBodyRef = useRef(null);

  useEffect(() => {
    // Generate client ID saat modal dibuka
    const newClientId = `client_${Math.random().toString(36).substring(2, 10)}`;
    setClientId(newClientId);

    return () => {
      // Cleanup on unmount
      handleCleanup();
    };
  }, []);

  const handleCleanup = () => {
    if (socket && socket.connected) {
      socket.disconnect();
    }
  };

  const initializeWebSocket = (cId) => {
    setStatus("Connecting to WebSocket...");

    const socketConnection = io(WS_URL, {
      query: { client_id: cId },
    });

    socketConnection.on("connect", () => {
      console.log("✅ Connected to WS as", cId);
      setStatus("Connected. Joining room...");
      
      socketConnection.emit("join_room", { room: cId });
    });

    socketConnection.on("joined", (data) => {
      console.log("🏠 Joined room:", data.room);
      setStatus("Room joined. Starting traffic monitoring...");
      
      startMonitoring(cId);
    });

    socketConnection.on("scan_status", (data) => {
      console.log("📡 Received scan_status:", data);
      
      if (data.status) {
        setStatus(data.status);
      }
      
      if (data.summary) {
        // Data baru ditambahkan di AWAL array (muncul di atas)
        setTrafficData((prev) => [{
          type: 'packet',
          data: data.summary,
          job: data.job,
          timestamp: new Date().toLocaleTimeString()
        }, ...prev]);
        
        setStatus(`Monitoring active - ${trafficData.length + 1} packets received`);
      }
    });

    socketConnection.on("scan_stopped", (data) => {
      console.log("🛑 Scan stopped:", data);
      setIsMonitoring(false);
      setStatus("Monitoring stopped");
    });

    socketConnection.onAny((event, data) => {
      console.log("📡 Any Event:", event, data);
    });

    socketConnection.on("disconnect", () => {
      console.log("❌ Disconnected from WebSocket");
      setStatus("Disconnected");
      setIsMonitoring(false);
    });

    socketConnection.on("connect_error", (error) => {
      console.error("Connection Error:", error);
      setStatus("Connection error: " + error.message);
      setIsStarting(false);
    });

    setSocket(socketConnection);
  };

  const startMonitoring = async (cId) => {
    try {
      setStatus("Sending API request to start monitoring...");
      
      const response = await api.post(API_ENDPOINTS.TRAFFIC, {
        ip: clientIp,
        client_id: cId,
      });

      console.log("🟢 API Response:", response.data);

      if (response.data.status === 1) {
        setIsMonitoring(true);
        setIsStarting(false);
        setStatus("Monitoring active - Waiting for traffic data...");
      } else {
        setStatus("Error: " + (response.data.message || "Failed to start monitoring"));
        setIsStarting(false);
        alert(response.data.message || "Failed to start monitoring");
      }
    } catch (error) {
      console.error("❌ Error starting monitoring:", error);
      setStatus("Error: " + error.message);
      setIsStarting(false);
      alert("Failed to start traffic monitoring: " + error.message);
    }
  };

  const handleStart = () => {
    if (!clientId) {
      console.error("No client ID available");
      return;
    }

    setIsStarting(true);
    setTrafficData([]);
    
    initializeWebSocket(clientId);
  };

  const handleStop = async () => {
    if (!clientId) {
      console.error("No client ID available");
      return;
    }

    setIsStopping(true);
    setStatus("Stopping monitoring...");

    try {
      console.log("📤 Sending stop request with client_id:", clientId);
      
      const response = await api.post(API_ENDPOINTS.TRAFFIC_STOP, {
        client_id: clientId,
      });

      console.log("🟢 Stop API Response:", response.data);

      if (response.data.status === 1) {
        setStatus("Monitoring stopped successfully");
        setIsMonitoring(false);
        
        if (socket && socket.connected) {
          socket.disconnect();
        }
      } else {
        setStatus("Error stopping: " + (response.data.message || "Unknown error"));
        alert(response.data.message || "Failed to stop monitoring");
      }
    } catch (error) {
      console.error("❌ Error stopping monitoring:", error);
      setStatus("Error: " + error.message);
      alert("Failed to stop traffic monitoring: " + error.message);
    } finally {
      setIsStopping(false);
    }
  };

  const handleClose = () => {
    if (isMonitoring) {
      const confirm = window.confirm("Traffic monitoring is still active. Do you want to stop it?");
      if (confirm) {
        handleStop();
        setTimeout(() => {
          handleCleanup();
          onClose();
        }, 500);
      }
    } else {
      handleCleanup();
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-lg w-full max-w-6xl h-[85vh] flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-slate-700 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Traffic Monitor</h2>
              <p className="text-sm text-slate-400">
                Client IP: <span className="text-blue-400">{clientIp}</span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {!isMonitoring && (
              <Button 
                onClick={handleStart}
                disabled={isStarting}
                className="mr-2 bg-green-600 hover:bg-green-700"
              >
                <Play className="w-4 h-4 mr-2" />
                {isStarting ? "Starting..." : "Start Monitoring"}
              </Button>
            )}
            
            {isMonitoring && (
              <Button 
                variant="danger" 
                onClick={handleStop} 
                disabled={isStopping}
                className="mr-2"
              >
                <Square className="w-4 h-4 mr-2" />
                {isStopping ? "Stopping..." : "Stop Monitoring"}
              </Button>
            )}
            
            <button
              onClick={handleClose}
              className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Status Bar */}
        <div className="px-6 py-3 bg-slate-800/50 border-b border-slate-700 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {isMonitoring && (
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              )}
              <p className="text-sm text-slate-300">
                Status: <span className={isMonitoring ? "text-green-400" : "text-blue-400"}>{status}</span>
              </p>
            </div>
            {clientId && (
              <p className="text-xs text-slate-500">
                Client ID: {clientId}
              </p>
            )}
          </div>
        </div>

        {/* Content - SCROLLABLE */}
        <div className="flex-1 overflow-hidden p-6 flex flex-col min-h-0">
          {!isMonitoring && !isStarting && trafficData.length === 0 && (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-16 h-16 bg-blue-600/20 rounded-full flex items-center justify-center mb-4">
                <Activity className="w-8 h-8 text-blue-400" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">Ready to Monitor Traffic</h3>
              <p className="text-slate-400 text-sm max-w-md">
                Click the "Start Monitoring" button above to begin capturing network traffic for {clientIp}
              </p>
            </div>
          )}

          {(isMonitoring || trafficData.length > 0) && (
            <>
              {/* Traffic Table - FIXED HEIGHT WITH SCROLL */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden flex-1 flex flex-col min-h-0">
                {/* Table Header - Fixed */}
                <div className="bg-slate-800/80 border-b border-slate-700 flex-shrink-0">
                  <table className="w-full table-fixed">
                    <thead>
                      <tr>
                        <th className="text-left p-4 text-sm font-medium text-slate-300 w-32">Timestamp</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-300 w-40">Source</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-300 w-40">Destination</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-300 w-24">Protocol</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-300 w-32">Port</th>
                        <th className="text-left p-4 text-sm font-medium text-slate-300 w-24">Length</th>
                      </tr>
                    </thead>
                  </table>
                </div>

                {/* Table Body - Scrollable */}
                <div ref={tableBodyRef} className="flex-1 overflow-y-auto">
                  <table className="w-full table-fixed">
                    <tbody className="divide-y divide-slate-700">
                      {trafficData.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="p-8 text-center text-slate-400">
                            {isMonitoring ? "Waiting for traffic data..." : "No data captured"}
                          </td>
                        </tr>
                      ) : (
                        trafficData.map((item, index) => (
                          <tr key={index} className="hover:bg-slate-800/30 transition-colors">
                            <td className="p-4 text-slate-300 text-sm font-mono w-32 truncate">
                              {item.timestamp}
                            </td>
                            <td className="p-4 text-green-400 font-mono text-sm w-40 truncate">
                              {item.data?.src || "-"}
                            </td>
                            <td className="p-4 text-blue-400 font-mono text-sm w-40 truncate">
                              {item.data?.dst || "-"}
                            </td>
                            <td className="p-4 w-24">
                              <span className="px-2 py-1 bg-blue-600/20 text-blue-400 border border-blue-500/50 rounded text-xs font-medium">
                                {item.data?.l4 || item.data?.protocol || "IP"}
                              </span>
                            </td>
                            <td className="p-4 text-slate-300 text-sm w-32 truncate">
                              {item.data?.sport && item.data?.dport 
                                ? `${item.data.sport} → ${item.data.dport}`
                                : "-"}
                            </td>
                            <td className="p-4 text-slate-300 text-sm w-24 truncate">
                              {item.data?.length || "-"} bytes
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Packet Count & Controls */}
              <div className="mt-4 flex items-center justify-between text-sm flex-shrink-0">
                <p className="text-slate-400">
                  Total packets captured: <span className="text-white font-medium">{trafficData.length}</span>
                </p>
                <button
                  onClick={() => setTrafficData([])}
                  disabled={isMonitoring}
                  className={`px-3 py-1.5 rounded text-xs transition-colors ${
                    isMonitoring 
                      ? 'bg-slate-700/50 text-slate-500 cursor-not-allowed' 
                      : 'bg-slate-700 hover:bg-slate-600 text-slate-300'
                  }`}
                >
                  Clear Data
                </button>
              </div>

              {/* Raw Data Display */}
              <div className="mt-4 flex-shrink-0">
                <details className="bg-slate-950 border border-slate-700 rounded">
                  <summary className="p-3 cursor-pointer text-white font-medium hover:bg-slate-900">
                    Raw Data (for debugging)
                  </summary>
                  <div className="p-4 max-h-60 overflow-auto">
                    <pre className="text-slate-300 text-xs">
                      {JSON.stringify(trafficData.slice(0, 10), null, 2)}
                      {trafficData.length > 10 && "\n... (showing first 10 packets)"}
                    </pre>
                  </div>
                </details>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default TrafficModal;