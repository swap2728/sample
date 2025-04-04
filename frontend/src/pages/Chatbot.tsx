import { useState } from "react";
import { Link } from "react-router-dom";
import { Briefcase, ShieldCheck, Globe, Cpu } from "lucide-react";

export default function Chatbot() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white p-6">
      <h2 className="text-4xl font-bold mb-10 text-center text-blue-400">Welcome to ODIN Chatbot</h2>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-8 w-full max-w-5xl">
        <Link to="/odin-business" className="group bg-gray-800 p-6 rounded-2xl shadow-lg transform transition hover:scale-105">
          <Briefcase className="w-10 h-10 text-blue-500" />
          <h3 className="text-2xl font-semibold">ODIN BUSINESS</h3>
          <p className="mt-4 text-gray-400">AI-powered intelligence for business and geopolitics.</p>
        </Link>

        <Link to="/odin-threat-intelligence" className="group bg-gray-800 p-6 rounded-2xl shadow-lg transform transition hover:scale-105">
          <ShieldCheck className="w-10 h-10 text-red-500" />
          <h3 className="text-2xl font-semibold">THREAT INTELLIGENCE</h3>
          <p className="mt-4 text-gray-400">AI-powered cybersecurity insights.</p>
        </Link>

        <Link to="/odin-crawler" className="group bg-gray-800 p-6 rounded-2xl shadow-lg transform transition hover:scale-105">
          <Globe className="w-10 h-10 text-yellow-500" />
          <h3 className="text-2xl font-semibold">ODIN CRAWLER</h3>
          <p className="mt-4 text-gray-400">Deep web and security intelligence gathering.</p>
        </Link>

        <Link to="/aegis" className="group bg-gray-800 p-6 rounded-2xl shadow-lg transform transition hover:scale-105">
          <Cpu className="w-10 h-10 text-green-500" />
          <h3 className="text-2xl font-semibold">AEGIS</h3>
          <p className="mt-4 text-gray-400">Enterprise AI core for security and intelligence.</p>
        </Link>
      </div>
    </div>
  );
}