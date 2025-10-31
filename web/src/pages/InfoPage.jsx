import React, { useState, useEffect } from "react";
import InfoCard from "../components/InfoCard";
import ClientTable from "../components/ClientTable";
import { Globe, Network, Server, Users, RefreshCw } from "lucide-react";
import { Button } from "../components/ui/button";
import { api, API_ENDPOINTS, BASE_URL } from "../config/api";

const InfoPage = () => {
  const [loading, setLoading] = useState(false);
  const [networkInfo, setNetworkInfo] = useState({
    ipAddress: null,
    interface: null,
    gateway: null,
    activeClients: null,
  });
  const [clients, setClients] = useState([]);

  useEffect(() => {
    fetchNetworkInfo();
  }, []);

  const fetchNetworkInfo = async () => {
    setLoading(true);
    try {
      // Get IP Address
      const ipResponse = await api.get(BASE_URL+"/info/ip-addr");
      
      // Get IP Gateway
      const ipGateway = await api.get(BASE_URL+"/info/ip-gateway");
      
      // Get Interface
      const interfaceResponse = await api.get(BASE_URL+"/info/active-interface");
      
      // Get Clients
      const clientsResponse = await api.post(BASE_URL+"/traffict/scan-ip", {
        module_name: "icmp",
      });

      if (ipResponse.data.status === 1) {
        setNetworkInfo((prev) => ({
          ...prev,
          ipAddress: ipResponse.data.data,
        }));
      }
      
      if (ipGateway.data.status === 1) {
        setNetworkInfo((prev) => ({
          ...prev,
          gateway: ipGateway.data.data,
        }));
      }

      if (interfaceResponse.data.status === 1) {
        setNetworkInfo((prev) => ({
          ...prev,
          interface: interfaceResponse.data.data,
        }));
      }

      if (clientsResponse.data.status === 1) {
        const clientsData = clientsResponse.data.data.map((client) => ({
          ip: client.ip,
          mac: client.mac,
          hostname: "-",
          status: "online",
          lastSeen: new Date().toLocaleString(),
        }));
        setClients(clientsData);
        setNetworkInfo((prev) => ({
          ...prev,
          activeClients: clientsData.length,
        }));
      } else {
        alert(clientsResponse.data.message);
      }
    } catch (error) {
      console.error("Error fetching network info:", error);
      alert("Failed to fetch network information");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Network Information</h1>
          <p className="text-slate-400">Monitor your network status and connected devices</p>
        </div>
        <Button onClick={fetchNetworkInfo} disabled={loading}>
          <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <InfoCard
          title="Your IP Address"
          value={networkInfo.ipAddress}
          subtitle="Public IP"
          icon={Globe}
        />
        <InfoCard
          title="Network Interface"
          value={networkInfo.interface}
          subtitle="192.168.1.0/24"
          icon={Network}
        />
        <InfoCard
          title="Gateway"
          value={networkInfo.gateway}
          subtitle="Default route"
          icon={Server}
        />
        <InfoCard
          title="Active Clients"
          value={networkInfo.activeClients}
          subtitle={`${networkInfo.activeClients} total devices`}
          icon={Users}
        />
      </div>

      {/* Connected Clients */}
      <div>
        <h2 className="text-2xl font-bold text-white mb-2">Connected Clients</h2>
        <p className="text-slate-400 mb-6">List of all devices on your network</p>
        <ClientTable clients={clients} />
      </div>
    </div>
  );
};

export default InfoPage;