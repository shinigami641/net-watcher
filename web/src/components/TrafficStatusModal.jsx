import React, { useEffect, useState } from "react";
import { X, Activity, RefreshCw, Trash2, AlertCircle } from "lucide-react";
import { Button } from "./ui/button";
import { api, API_ENDPOINTS, BASE_URL } from "../config/api";

const TrafficStatusModal = ({ onClose }) => {
  const [activeScans, setActiveScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async () => {
    setRefreshing(true);
    try {
      const response = await api.get(BASE_URL+"/traffict/status");
      
      if (response.data.status === 1) {
        setActiveScans(response.data.data.active_scans || []);
      } else {
        console.error("Failed to fetch status:", response.data.message);
      }
    } catch (error) {
      console.error("Error fetching traffic status:", error);
      alert("Failed to fetch traffic status");
    } finally {
      setRefreshing(false);
    }
  };

  const handleStopAll = async () => {
    const confirm = window.confirm(
        `Are you sure you want to stop all ${activeScans.length} active scan(s)?`
    );
    
    if (!confirm) return;

    setLoading(true);
    try {
        // Ubah ke POST
        const response = await api.post(BASE_URL+"/traffict/stop-all");
        
        if (response.data.status === 1) {
        const { stopped, failed } = response.data.data;
        alert(`Successfully stopped ${stopped.length} scan(s)${failed.length > 0 ? `, ${failed.length} failed` : ''}`);
        setActiveScans([]);
        fetchStatus(); // Refresh to confirm
        } else {
        alert(response.data.message || "Failed to stop all scans");
        }
    } catch (error) {
        console.error("Error stopping all scans:", error);
        alert("Failed to stop all scans: " + error.message);
    } finally {
        setLoading(false);
    }
    };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-lg w-full max-w-4xl max-h-[70vh] flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Active Traffic Scans</h2>
              <p className="text-sm text-slate-400">
                {activeScans.length} active scan{activeScans.length !== 1 ? 's' : ''}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              onClick={fetchStatus}
              disabled={refreshing}
              className="mr-2"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            {activeScans.length > 0 && (
              <Button
                variant="danger"
                onClick={handleStopAll}
                disabled={loading}
                className="mr-2"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                {loading ? "Stopping..." : "Stop All"}
              </Button>
            )}
            <button
              onClick={onClose}
              className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800 text-slate-400"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {activeScans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-16 h-16 bg-slate-800 rounded-full flex items-center justify-center mb-4">
                <AlertCircle className="w-8 h-8 text-slate-500" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">No Active Scans</h3>
              <p className="text-slate-400 text-sm">
                There are currently no active traffic scans running.
              </p>
            </div>
          ) : (
            <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-slate-800/80 border-b border-slate-700">
                  <tr>
                    <th className="text-left p-4 text-sm font-medium text-slate-300">Job ID</th>
                    <th className="text-left p-4 text-sm font-medium text-slate-300">Client ID</th>
                    <th className="text-left p-4 text-sm font-medium text-slate-300">Target IP</th>
                    <th className="text-center p-4 text-sm font-medium text-slate-300">Thread Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                  {activeScans.map((scan, index) => (
                    <tr key={index} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-4 text-slate-300 font-mono text-sm">
                        {scan.job_id.substring(0, 8)}...
                      </td>
                      <td className="p-4 text-blue-400 font-mono text-sm">
                        {scan.client_id}
                      </td>
                      <td className="p-4 text-white text-sm">
                        {scan.ip}
                      </td>
                      <td className="p-4 text-center">
                        {scan.thread_alive ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-green-500/20 text-green-400 border border-green-500/50 rounded text-xs font-medium">
                            <span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse"></span>
                            Running
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-slate-500/20 text-slate-400 border border-slate-500/50 rounded text-xs font-medium">
                            <span className="w-1.5 h-1.5 bg-slate-400 rounded-full"></span>
                            Stopped
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Footer Info */}
        {activeScans.length > 0 && (
          <div className="p-4 border-t border-slate-700 bg-slate-800/30">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <AlertCircle className="w-4 h-4" />
              <span>
                Active scans are consuming system resources. Use "Stop All" to terminate all monitoring sessions.
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TrafficStatusModal;