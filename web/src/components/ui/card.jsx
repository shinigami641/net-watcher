import React from "react";

export const Card = ({ children, className = "" }) => {
  return (
    <div className={`bg-slate-800/50 border border-slate-700 rounded-lg ${className}`}>
      {children}
    </div>
  );
};

export const CardContent = ({ children, className = "" }) => {
  return (
    <div className={`p-6 ${className}`}>
      {children}
    </div>
  );
};