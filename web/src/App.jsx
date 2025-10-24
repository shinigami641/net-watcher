import React, { useState } from "react";
import Sidebar from "./components/Sidebar";
import InfoPage from "./pages/InfoPage";
import TrafficScanPage from "./pages/TrafficScanPage";

function App() {
  const [activePage, setActivePage] = useState("info");

  const renderPage = () => {
    switch (activePage) {
      case "info":
        return <InfoPage />;
      case "traffic":
        return <TrafficScanPage />;
      default:
        return <InfoPage />;
    }
  };

  return (
    <div className="flex h-screen bg-slate-950">
      <Sidebar activePage={activePage} onNavigate={setActivePage} />
      <main className="flex-1 overflow-auto">
        {renderPage()}
      </main>
    </div>
  );
}

export default App;