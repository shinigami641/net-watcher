import React from "react";
import { Button } from "./ui/button";
import { Wifi, Info as InfoIcon, Activity, ChevronDown, Syringe } from "lucide-react";

const Sidebar = ({ activePage, onNavigate }) => {
  const [scanExpanded, setScanExpanded] = React.useState(true);

  return (
    <div className="w-52 bg-slate-900 border-r border-slate-800 h-screen flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
            <Wifi className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">NetWatcher</h1>
            <p className="text-xs text-slate-400">Network Panel</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1">
        {/* Info Button */}
        <button
          onClick={() => onNavigate("info")}
          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
            activePage === "info"
              ? "bg-slate-800 text-white"
              : "text-slate-400 hover:bg-slate-800/50 hover:text-white"
          }`}
        >
          <InfoIcon className="w-4 h-4" />
          Info
        </button>

        {/* Scan Dropdown */}
        <div>
          <button
            onClick={() => setScanExpanded(!scanExpanded)}
            className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
              activePage === "traffic" || scanExpanded
                ? "bg-slate-800 text-white"
                : "text-slate-400 hover:bg-slate-800/50 hover:text-white"
            }`}
          >
            <div className="flex items-center gap-3">
              <Activity className="w-4 h-4" />
              Scan
            </div>
            <ChevronDown
              className={`w-4 h-4 transition-transform ${
                scanExpanded ? "rotate-180" : ""
              }`}
            />
          </button>

          {/* Sub Menu */}
          {scanExpanded && (
            <div className="mt-1 ml-3 pl-4 border-l border-slate-700">
              <button
                onClick={() => onNavigate("traffic")}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                  activePage === "traffic"
                    ? "bg-blue-600 text-white font-medium"
                    : "text-slate-400 hover:bg-slate-800/50 hover:text-white"
                }`}
              >
                <span className="text-xs">•</span>
                Traffic Scan
              </button>
            </div>
          )}
        </div>

        {/* Arp Spoofing Button */}
        <button
          onClick={() => onNavigate("arp")}
          className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
            activePage === "arp"
              ? "bg-slate-800 text-white"
              : "text-slate-400 hover:bg-slate-800/50 hover:text-white"
          }`}
        >
          <Syringe className="w-4 h-4" />
          Arp Spoofing
        </button>
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
          <div>
            <p className="text-white text-sm font-medium">System Active</p>
            <p className="text-slate-400 text-xs">Monitoring in progress</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;