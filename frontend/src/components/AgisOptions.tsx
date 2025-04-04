import { useState } from "react";

export default function AgisOptions() {
  const [aegisStatus] = useState("Under Development");

  return (
    <div className="flex flex-col items-center justify-center h-screen bg-gradient-to-r from-gray-700 to-gray-900 text-white">
      <div className="bg-black bg-opacity-50 p-8 rounded-2xl shadow-lg text-center animate-fade-in">
        <h2 className="text-4xl font-extrabold mb-4 tracking-wide">🛡 Aegis – The AI Core</h2>
        <p className="text-lg opacity-90">
          Aegis embeds itself into your servers, delivering <br />
          <span className="text-green-400 animate-pulse">AI-driven security insights</span>.
        </p>
        <button 
          className="bg-green-600 text-white px-4 py-2 rounded-lg cursor-not-allowed opacity-50 mt-4"
          disabled
        >
          → Integrate Aegis Now (Status: {aegisStatus})
        </button>
      </div>
    </div>
  );
}