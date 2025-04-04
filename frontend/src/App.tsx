import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import WelcomeScreen from "./components/WelcomeScreen";
import Chatbot from "./pages/Chatbot";  // Updated from Dashboard to Chatbot
import OdinBusiness from "./pages/OdinBusiness";
import DataReport from "./pages/DataReport";
import OdinThreatIntelligence from "./pages/OdinThreatIntelligence";
import OdinCrawler from "./pages/OdinCrawler";
import ChatInterface from "./components/ChatInterface";
import AgisOptions from "./components/AgisOptions"; 

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<WelcomeScreen onStart={() => window.location.href = "/chatbot"} />} />
        <Route path="/chatbot" element={<Chatbot />} />  {/* Updated Route */}
        <Route path="/odin-business" element={<OdinBusiness />} />
        <Route path="/data-report" element={<DataReport />} />
        <Route path="/odin-threat-intelligence" element={<OdinThreatIntelligence />} />
        <Route path="/odin-crawler" element={<OdinCrawler />} />
        <Route path="/chat" element={<ChatInterface />} />
        <Route path="/aegis" element={<AgisOptions />} />
      </Routes>
    </Router>
  );
}