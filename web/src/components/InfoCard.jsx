import React from "react";
import { Card, CardContent } from "./ui/card";

const InfoCard = ({ title, value, subtitle, icon: Icon }) => {
  return (
    <Card>
      <CardContent>
        <div className="flex items-start justify-between">
          <div>
            <p className="text-slate-400 text-sm mb-2">{title}</p>
            <h3 className="text-2xl font-bold text-white mb-1">{value || "Loading..."}</h3>
            <p className="text-slate-500 text-xs">{subtitle}</p>
          </div>
          {Icon && (
            <div className="w-10 h-10 bg-blue-600/20 rounded-lg flex items-center justify-center">
              <Icon className="w-5 h-5 text-blue-400" />
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default InfoCard;