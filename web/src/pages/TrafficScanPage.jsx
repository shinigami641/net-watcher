import React, { useState, useEffect } from "react";
import { Eye, TrendingUp, Activity as ActivityIcon, Users, ListChecks } from "lucide-react";
import { Card, CardContent } from "../components/ui/card";
import { Button } from "../components/ui/button";
import TrafficModal from "../components/TrafficModal";
import TrafficStatusModal from "../components/TrafficStatusModal";
import { api, API_ENDPOINTS, BASE_URL } from "../config/api";

const TrafficScanPage = () => {
  const [clients, setClients] = useState([]);
  const [selectedClient, setSelectedClient] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [showStatusModal, setShowStatusModal] = useState(false);

  useEffect(() => {
    fetchClients();
  }, []);

  const fetchClients = async () => {
    try {
      const response = await api.post(BASE_URL+"/traffict/scan-ip", {
        module_name: "icmp",
      });

      if (response.data.status === 1) {
        const clientsData = response.data.data.map((client) => ({
          ip: client.ip,
          mac: client.mac,
          hostname: "-",
          status: "online",
          lastActivity: new Date().toLocaleString(),
        }));
        setClients(clientsData);
      } else {
        alert(response.data.message);
      }
    } catch (error) {
      console.error("Error fetching clients:", error);
    }
  };

  const handleViewTraffic = (client) => {
    setSelectedClient(client);
    setShowModal(true);
  };

  const StatusBadge = ({ status }) => {
    const styles = {
      online: "bg-green-500/20 text-green-400 border-green-500/50",
      idle: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
      offline: "bg-slate-500/20 text-slate-400 border-slate-500/50",
    };

    return (
      <span className={`px-2 py-1 rounded text-xs font-medium border inline-flex items-center gap-1 ${styles[status]}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
        {status}
      </span>
    );
  };

  const activeCount = clients.filter(c => c.status === "online").length;

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center">
            <ActivityIcon className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-white">Traffic Scan</h1>
            <p className="text-slate-400">Monitor network traffic for all connected clients</p>
          </div>
        </div>
        
        {/* Button to show active scans */}
        <Button 
          onClick={() => setShowStatusModal(true)}
          className="flex items-center gap-2"
        >
          <ListChecks className="w-4 h-4" />
          Active Scans Status
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card>
          <CardContent>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-2">Clients Monitored</p>
                <h3 className="text-2xl font-bold text-white mb-1">{clients.length}</h3>
                <p className="text-slate-500 text-xs">Total devices</p>
              </div>
              <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
                <TrendingUp className="w-5 h-5 text-blue-400" />
              </div>
            </div>
            <div className="mt-3 flex items-center gap-2">
              <span className="px-2 py-1 bg-green-500/20 text-green-400 border border-green-500/50 rounded text-xs font-medium">
                Live
              </span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-2">Active Connections</p>
                <h3 className="text-2xl font-bold text-white mb-1">{activeCount}</h3>
                <p className="text-slate-500 text-xs">Currently online</p>
              </div>
              <div className="w-10 h-10 bg-green-600/20 rounded-lg flex items-center justify-center">
                <ActivityIcon className="w-5 h-5 text-green-400" />
              </div>
            </div>
            <div className="mt-3">
              <span className="w-2 h-2 bg-green-500 rounded-full inline-block mr-2"></span>
              <span className="text-slate-400 text-xs">Real-time monitoring</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent>
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm mb-2">Monitoring Mode</p>
                <h3 className="text-2xl font-bold text-white mb-1">Real-time</h3>
                <p className="text-slate-500 text-xs">Active scanning</p>
              </div>
              <div className="w-10 h-10 bg-purple-600/20 rounded-lg flex items-center justify-center">
                <Eye className="w-5 h-5 text-purple-400" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Client Traffic Monitor */}
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">Client Traffic Monitor</h2>
        <p className="text-slate-400 mb-6">Click the eye icon to view detailed traffic data</p>

        <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-slate-800/80 border-b border-slate-700">
              <tr>
                <th className="text-left p-4 text-sm font-medium text-slate-300">IP Address</th>
                <th className="text-left p-4 text-sm font-medium text-slate-300">Mac</th>
                <th className="text-left p-4 text-sm font-medium text-slate-300">Status</th>
                <th className="text-left p-4 text-sm font-medium text-slate-300">Last Activity</th>
                <th className="text-right p-4 text-sm font-medium text-slate-300">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700">
              {clients.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-slate-400">
                    No clients found. Please scan for devices first.
                  </td>
                </tr>
              ) : (
                clients.map((client, index) => (
                  <tr key={index} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 text-blue-400 font-mono text-sm">{client.ip}</td>
                    <td className="p-4 text-white text-sm">{client.mac}</td>
                    <td className="p-4">
                      <StatusBadge status={client.status} />
                    </td>
                    <td className="p-4 text-slate-400 text-sm">{client.lastActivity}</td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => handleViewTraffic(client)}
                        className="inline-flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                        View Traffic
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Traffic Modal */}
      {showModal && selectedClient && (
        <TrafficModal
          clientIp={selectedClient.ip}
          onClose={() => {
            setShowModal(false);
            setSelectedClient(null);
          }}
        />
      )}

      {/* Traffic Status Modal */}
      {showStatusModal && (
        <TrafficStatusModal
          onClose={() => setShowStatusModal(false)}
        />
      )}
    </div>
  );
};

export default TrafficScanPage;