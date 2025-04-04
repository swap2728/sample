import { useNavigate } from "react-router-dom";
import React from "react";

export default function OdinThreatIntelligence() {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-800 p-6">
      <div className="text-center max-w-2xl">
        <h1 className="text-4xl font-bold text-white mb-6">ODIN Threat Intelligence</h1>
        <p className="text-lg text-gray-300 mb-8">
          Advanced threat intelligence platform for security analysis and monitoring
        </p>

        <button
          onClick={() => navigate("/chat")}
          className="px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-300 text-lg font-medium"
        >
          Go to Chat
        </button>
      </div>
    </div>
  );
}