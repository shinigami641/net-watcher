import React from "react";

const StatusBadge = ({ status }) => {
  const styles = {
    online: "bg-green-500/20 text-green-400 border-green-500/50",
    idle: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
    offline: "bg-slate-500/20 text-slate-400 border-slate-500/50",
  };

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium border ${styles[status] || styles.offline}`}>
      {status}
    </span>
  );
};

const ClientTable = ({ clients, showHostname = true, showLastSeen = true }) => {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
      <table className="w-full">
        <thead className="bg-slate-800/80 border-b border-slate-700">
          <tr>
            <th className="text-left p-4 text-sm font-medium text-slate-300">IP Address</th>
            {showHostname && <th className="text-left p-4 text-sm font-medium text-slate-300">Hostname</th>}
            <th className="text-left p-4 text-sm font-medium text-slate-300">MAC Address</th>
            <th className="text-left p-4 text-sm font-medium text-slate-300">Status</th>
            {showLastSeen && <th className="text-left p-4 text-sm font-medium text-slate-300">Last Seen</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-700">
          {clients.length === 0 ? (
            <tr>
              <td colSpan={showHostname && showLastSeen ? 5 : 4} className="p-8 text-center text-slate-400">
                No clients found
              </td>
            </tr>
          ) : (
            clients.map((client, index) => (
              <tr key={index} className="hover:bg-slate-800/30 transition-colors">
                <td className="p-4 text-blue-400 font-mono text-sm">{client.ip}</td>
                {showHostname && <td className="p-4 text-white text-sm">{client.hostname || "-"}</td>}
                <td className="p-4 text-slate-400 font-mono text-sm">{client.mac}</td>
                <td className="p-4">
                  <StatusBadge status={client.status || "offline"} />
                </td>
                {showLastSeen && <td className="p-4 text-slate-400 text-sm">{client.lastSeen || "-"}</td>}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
};

export default ClientTable;