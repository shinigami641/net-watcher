import React from "react";

export const Button = ({ children, variant = "default", className = "", ...props }) => {
  const baseStyles = "px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  
  const variants = {
    default: "bg-blue-600 hover:bg-blue-700 text-white",
    ghost: "hover:bg-slate-700 text-slate-300",
    danger: "bg-red-600 hover:bg-red-700 text-white",
  };

  return (
    <button 
      className={`${baseStyles} ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};