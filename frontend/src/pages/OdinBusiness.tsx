import { Link } from "react-router-dom";

export default function OdinBusiness() {
  return (
    <div className="flex flex-col items-center justify-center h-screen bg-gray-300">
      <h2 className="text-2xl font-bold mb-6">ODIN BUSINESS</h2>
      <div className="flex space-x-4">
        <Link to="/data-report" className="px-6 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700">
          Data Report
        </Link>
        <a href="https://www.geopoliticalmonitor.com/" target="_blank" rel="noopener noreferrer"
          className="px-6 py-3 bg-orange-600 text-white rounded-lg hover:bg-orange-700">
          Geopolitical News
        </a>
      </div>
    </div>
  );
}
