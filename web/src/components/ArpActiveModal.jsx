import React, { useEffect, useState } from "react";
import { X, Activity, RefreshCw, Trash2, Info } from "lucide-react";
import { Button } from "./ui/button";
import { api, BASE_URL } from "../config/api";

const ArpActiveModal = ({ onClose, clientId }) => {
  const [activeAttacks, setActiveAttacks] = useState([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedDetail, setSelectedDetail] = useState(null);

  useEffect(() => {
    fetchActive();
  }, []);

  const normalizeActive = (data) => {
    // backend returns a dict of job_id -> scan_data
    if (!data) return [];
    if (Array.isArray(data)) return data; // in case backend already returns array
    const arr = Object.entries(data).map(([job_id, rec]) => ({
      job_id,
      client_id: rec?.client_id,
      ip: rec?.ip,
      gateway_ip: rec?.gateway_ip,
      interface: rec?.interface,
      started_at: rec?.started_at,
      target_mac: rec?.target_mac,
      gateway_mac: rec?.gateway_mac,
    }));
    return arr;
  };

  const fetchActive = async () => {
    setRefreshing(true);
    try {
      const response = await api.get(`${BASE_URL}/arp/all-active`);
      if (response.data.status === 1) {
        setActiveAttacks(normalizeActive(response.data.data));
      } else {
        alert(response.data.message || "Gagal mengambil data aktif");
      }
    } catch (error) {
      console.error("Error fetching ARP active:", error);
      alert("Gagal mengambil data aktif");
    } finally {
      setRefreshing(false);
    }
  };

  const viewDetail = async (cid) => {
    setLoading(true);
    setSelectedDetail(null);
    try {
      const response = await api.post(`${BASE_URL}/arp/status`, {
        client_id: cid,
      });
      if (response.data.status === 1) {
        setSelectedDetail(response.data.data);
      } else {
        alert(response.data.message || "Gagal mengambil detail status");
      }
    } catch (error) {
      console.error("Error fetching ARP status:", error);
      alert("Gagal mengambil detail status");
    } finally {
      setLoading(false);
    }
  };

  const handleStopAll = async () => {
    const confirmStop = window.confirm(
      `Yakin ingin menghentikan semua (${activeAttacks.length}) ARP attack?`
    );
    if (!confirmStop) return;

    setLoading(true);
    try {
      // backend supports GET and POST; use POST here
      const response = await api.post(`${BASE_URL}/arp/stop-all`);
      if (response.data.status === 1) {
        const { stopped_count, failed_count } = response.data.data;
        alert(`Berhasil stop ${stopped_count} attack${failed_count ? ", gagal: " + failed_count : ""}`);
        setActiveAttacks([]);
        fetchActive();
      } else {
        alert(response.data.message || "Gagal menghentikan semua attack");
      }
    } catch (error) {
      console.error("Error stopping all ARP attacks:", error);
      alert("Gagal menghentikan semua attack");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-lg w-full max-w-5xl max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-slate-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
              <Activity className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Active ARP Attacks</h2>
              <p className="text-sm text-slate-400">
                {activeAttacks.length} aktif
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={fetchActive} disabled={refreshing} className="mr-2">
              <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            {activeAttacks.length > 0 && (
              <Button variant="danger" onClick={handleStopAll} disabled={loading} className="mr-2">
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
          {activeAttacks.length === 0 ? (
            <div className="text-slate-400 text-sm">Tidak ada ARP attack yang aktif.</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-slate-800/80 border-b border-slate-700">
                    <tr>
                      <th className="text-left p-4 text-sm font-medium text-slate-300">Job ID</th>
                      <th className="text-left p-4 text-sm font-medium text-slate-300">Client ID</th>
                      <th className="text-left p-4 text-sm font-medium text-slate-300">Target IP</th>
                      <th className="text-right p-4 text-sm font-medium text-slate-300">Aksi</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {activeAttacks.map((scan, index) => (
                      <tr key={index} className="hover:bg-slate-800/30 transition-colors">
                        <td className="p-4 text-slate-300 font-mono text-sm">{String(scan.job_id).slice(0, 8)}...</td>
                        <td className="p-4 text-blue-400 font-mono text-sm">{scan.client_id}</td>
                        <td className="p-4 text-white text-sm">{scan.ip}</td>
                        <td className="p-4 text-right">
                          <Button size="sm" variant="outline" onClick={() => viewDetail(scan.client_id)}>
                            <Info className="w-4 h-4 mr-2" /> Detail
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <h3 className="text-white font-semibold mb-2">Detail</h3>
                {!selectedDetail ? (
                  <p className="text-slate-400 text-sm">Pilih baris untuk melihat detail status.</p>
                ) : (
                  <div className="space-y-2 text-sm">
                    <div className="text-slate-300"><span className="text-slate-400">Job:</span> {selectedDetail.job_id}</div>
                    <div className="text-slate-300"><span className="text-slate-400">Client:</span> {selectedDetail.client_id}</div>
                    <div className="text-slate-300"><span className="text-slate-400">IP Target:</span> {selectedDetail.ip}</div>
                    <div className="text-slate-300"><span className="text-slate-400">Gateway:</span> {selectedDetail.gateway_ip}</div>
                    <div className="text-slate-300"><span className="text-slate-400">Interface:</span> {selectedDetail.interface}</div>
                    <div className="text-slate-300"><span className="text-slate-400">Uptime:</span> {Math.round(selectedDetail.uptime)}s</div>
                    <div className="text-slate-300"><span className="text-slate-400">Thread:</span> {selectedDetail.thread_info?.name} ({selectedDetail.thread_info?.is_alive ? "alive" : "stopped"})</div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ArpActiveModal;