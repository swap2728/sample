import { useState, useEffect } from "react";
import { X, ExternalLink, ShieldAlert, Bitcoin, Mail, Phone } from "lucide-react";

interface DarkWebOptionsProps {
  onClose: () => void;
}

interface ExtractionResult {
  success: boolean;
  metadata?: {
    title: string;
    url: string;
    headers: Array<{ level: string; text: string }>;
    links: Array<{ text: string; url: string; is_external: boolean }>;
    forms: Array<{
      action: string;
      method: string;
      inputs: Array<{ type: string; name: string }>;
    }>;
    stats: {
      word_count: number;
      link_count: number;
      image_count: number;
      common_words: Record<string, number>;
    };
    security_indicators: string[];
  };
  sensitive_info?: Array<{
    category: string;
    keywords: string[];
    matches: string[];
  }>;
  indicators?: {
    bitcoin_addresses: string[];
    email_addresses: string[];
    phone_numbers: string[];
  };
  stats?: {
    page_size: number;
    load_time: number;
    status_code: number;
  };
  darkwebResults?: Array<{
    title: string;
    url: string;
    description: string;
    category: string;
    source: string;
    type: string;
  }>;
  error?: string;
}

interface TorStatus {
  status: string;
  instructions?: string;
  port?: number;
}

export default function DarkWebOptions({ onClose }: DarkWebOptionsProps) {
  const [onionUrl, setOnionUrl] = useState("");
  const [searchKeyword, setSearchKeyword] = useState("");
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"extract" | "search">("extract");
  const [response, setResponse] = useState<ExtractionResult | null>(null);
  const [torStatus, setTorStatus] = useState<TorStatus>({ 
    status: "Checking Tor status...",
    instructions: "Please wait while we verify your Tor connection"
  });

  useEffect(() => {
    const checkTorStatus = async () => {
      try {
        const res = await fetch("http://localhost:8000/api/tor-status/");
        const data = await res.json();
        setTorStatus(data);
      } catch (err) {
        setTorStatus({
          status: "Connection failed",
          instructions: "Could not reach Tor status service. Is the backend running?"
        });
      }
    };
    checkTorStatus();
  }, []);

  const handleRequest = async () => {
    setLoading(true);
    setResponse(null);
  
    try {
      const endpoint = "http://localhost:8000/api/dark-web/";
      const formData = new URLSearchParams();
      formData.append("action", activeTab);
      
      if (activeTab === "extract") {
        formData.append("onion_url", onionUrl);
      } else {
        formData.append("keyword", searchKeyword);
      }

      const res = await fetch(endpoint, {
        method: "POST",
        headers: { 
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formData
      });

      const data = await res.json();
      
      if (!res.ok) {
        let errorMsg = data.error || `HTTP error ${res.status}`;
        if (res.status === 503) {
          errorMsg = `Tor Connection Error\n\n${errorMsg}\n\n` +
            `Troubleshooting:\n` +
            `1. Ensure Tor Browser is running\n` +
            `2. Verify no firewall blocks connections\n` +
            `3. Try restarting Tor\n` +
            `4. Check backend service is running`;
        }
        throw new Error(errorMsg);
      }

      setResponse(data);
    } catch (error: any) {
      setResponse({ 
        success: false, 
        error: error.message || "An unknown error occurred" 
      });
    } finally {
      setLoading(false);
    }
  };

  const renderSearchResults = () => {
    if (!response?.darkwebResults) return null;
    
    return (
      <div className="space-y-4">
        <h3 className="font-bold text-lg">Search Results</h3>
        <div className="grid grid-cols-1 gap-3">
          {response.darkwebResults.map((result, i) => (
            <div key={i} className="border border-gray-700 rounded-lg p-3 hover:bg-[#40414F]/50 transition-colors">
              <div className="flex justify-between items-start">
                <div>
                  <h4 className="text-blue-400 font-medium flex items-center gap-2">
                    <ExternalLink className="w-4 h-4" />
                    {result.title}
                  </h4>
                  <div className="text-xs text-gray-400 mt-1 break-all">
                    URL: <span className="text-yellow-400">{result.url}</span>
                  </div>
                  <div className="text-xs text-gray-400 mt-1">
                    Source: <span className="text-yellow-400">{result.source}</span> • 
                    Category: <span className="text-purple-400">{result.category}</span> • 
                    Type: <span className="text-green-400">{result.type}</span>
                  </div>
                </div>
                <a 
                  href={result.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-xs bg-[#292B35] hover:bg-[#40414F] px-2 py-1 rounded"
                >
                  Visit
                </a>
              </div>
              {result.description && (
                <p className="text-sm text-gray-300 mt-2">
                  {result.description}
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    );
  };

  const renderExtractionResults = () => {
    if (!response?.metadata) return null;
    
    return (
      <div className="space-y-6">
        <div className="border-b border-gray-700 pb-4">
          <h3 className="font-bold text-lg mb-2">Page Information</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-sm text-gray-400 mb-1">Title</h4>
              <div className="bg-[#40414F] p-2 rounded break-all">
                {response.metadata.title}
              </div>
            </div>
            <div>
              <h4 className="text-sm text-gray-400 mb-1">URL</h4>
              <div className="bg-[#40414F] p-2 rounded break-all">
                {response.metadata.url}
              </div>
            </div>
            {response.stats && (
              <>
                <div>
                  <h4 className="text-sm text-gray-400 mb-1">Page Size</h4>
                  <div className="bg-[#40414F] p-2 rounded">
                    {(response.stats.page_size / 1024).toFixed(2)} KB
                  </div>
                </div>
                <div>
                  <h4 className="text-sm text-gray-400 mb-1">Load Time</h4>
                  <div className="bg-[#40414F] p-2 rounded">
                    {response.stats.load_time.toFixed(2)} seconds
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h4 className="font-semibold">Headers Structure</h4>
            <div className="bg-[#40414F] p-3 rounded max-h-60 overflow-y-auto">
              {response.metadata.headers.length > 0 ? (
                <ul className="space-y-2">
                  {response.metadata.headers.map((header, i) => (
                    <li key={i} className="text-sm">
                      <span className="text-yellow-400">{header.level}:</span> {header.text}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-gray-400">No headers detected</p>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="font-semibold">Security Indicators</h4>
            <div className="bg-[#40414F] p-3 rounded max-h-60 overflow-y-auto">
              {response.metadata.security_indicators.length > 0 ? (
                <ul className="space-y-2">
                  {response.metadata.security_indicators.map((indicator, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                      {indicator}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-gray-400">No security issues detected</p>
              )}
            </div>
          </div>
        </div>

        {response.indicators && (
          <div className="space-y-4">
            <h4 className="font-semibold">Found Indicators</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {response.indicators.bitcoin_addresses.length > 0 && (
                <div className="bg-[#292B35] p-3 rounded">
                  <div className="flex items-center gap-2 text-yellow-400 mb-2">
                    <Bitcoin className="w-4 h-4" />
                    <h5 className="font-medium">Bitcoin Addresses</h5>
                  </div>
                  <ul className="text-xs space-y-1 break-all">
                    {response.indicators.bitcoin_addresses.map((addr, i) => (
                      <li key={i}>{addr}</li>
                    ))}
                  </ul>
                </div>
              )}
              {response.indicators.email_addresses.length > 0 && (
                <div className="bg-[#292B35] p-3 rounded">
                  <div className="flex items-center gap-2 text-blue-400 mb-2">
                    <Mail className="w-4 h-4" />
                    <h5 className="font-medium">Email Addresses</h5>
                  </div>
                  <ul className="text-xs space-y-1 break-all">
                    {response.indicators.email_addresses.map((email, i) => (
                      <li key={i}>{email}</li>
                    ))}
                  </ul>
                </div>
              )}
              {response.indicators.phone_numbers.length > 0 && (
                <div className="bg-[#292B35] p-3 rounded">
                  <div className="flex items-center gap-2 text-green-400 mb-2">
                    <Phone className="w-4 h-4" />
                    <h5 className="font-medium">Phone Numbers</h5>
                  </div>
                  <ul className="text-xs space-y-1">
                    {response.indicators.phone_numbers.map((phone, i) => (
                      <li key={i}>{phone}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {response.sensitive_info && response.sensitive_info.length > 0 && (
          <div className="space-y-4">
            <h4 className="font-semibold">Sensitive Information</h4>
            <div className="bg-[#292B35] p-4 rounded">
              {response.sensitive_info.map((info, i) => (
                <div key={i} className="mb-3 last:mb-0">
                  <div className="font-medium text-red-400">{info.category}</div>
                  {info.keywords.length > 0 && (
                    <div className="text-sm mt-1">
                      <span className="text-gray-400">Keywords:</span> {info.keywords.join(", ")}
                    </div>
                  )}
                  {info.matches.length > 0 && (
                    <div className="text-sm mt-1">
                      <span className="text-gray-400">Matches:</span> {info.matches.join(", ")}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-[#343541] rounded-lg p-6 w-full max-w-4xl relative max-h-[90vh] overflow-y-auto">
        <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-white">
          <X className="w-6 h-6" />
        </button>
        
        <h2 className="text-xl text-white font-semibold mb-4">Dark Web Operations</h2>
        
        <div className="mb-4 p-3 bg-[#292B35] rounded-lg">
          <div className="flex items-center">
            <span className="mr-2">Tor Status:</span>
            <span className={
              torStatus.status.includes("Running") ? "text-green-400" : 
              torStatus.status.includes("fail") ? "text-red-400" : "text-yellow-400"
            }>
              {torStatus.status}
              {torStatus.port && ` (port ${torStatus.port})`}
            </span>
          </div>
          {torStatus.instructions && (
            <div className="text-sm text-gray-400 mt-1 whitespace-pre-line">
              {torStatus.instructions}
            </div>
          )}
        </div>

        <div className="flex border-b border-gray-600 mb-4">
          <button
            className={`py-2 px-4 ${activeTab === "extract" ? "text-white border-b-2 border-blue-500" : "text-gray-400"}`}
            onClick={() => setActiveTab("extract")}
          >
            Extract Data
          </button>
          <button
            className={`py-2 px-4 ${activeTab === "search" ? "text-white border-b-2 border-blue-500" : "text-gray-400"}`}
            onClick={() => setActiveTab("search")}
          >
            Search Dark Web
          </button>
        </div>

        {activeTab === "extract" ? (
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">
                .onion URL
              </label>
              <input
                type="text"
                value={onionUrl}
                onChange={(e) => setOnionUrl(e.target.value)}
                placeholder="http://example.onion"
                className="w-full p-3 rounded-lg bg-[#40414F] text-white placeholder-gray-400"
              />
            </div>
            <button
              onClick={handleRequest}
              disabled={loading || !onionUrl}
              className={`w-full p-3 rounded-lg ${
                loading || !onionUrl
                  ? "bg-gray-600 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-700"
              } text-white font-medium transition-colors`}
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Processing...
                </span>
              ) : "Extract Data"}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">
                Search Keyword
              </label>
              <input
                type="text"
                value={searchKeyword}
                onChange={(e) => setSearchKeyword(e.target.value)}
                placeholder="e.g. marketplace, forum, leaks"
                className="w-full p-3 rounded-lg bg-[#40414F] text-white placeholder-gray-400"
              />
            </div>
            <button
              onClick={handleRequest}
              disabled={loading || !searchKeyword}
              className={`w-full p-3 rounded-lg ${
                loading || !searchKeyword
                  ? "bg-gray-600 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-700"
              } text-white font-medium transition-colors`}
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Searching...
                </span>
              ) : "Search Dark Web"}
            </button>
          </div>
        )}

        {response && (
          <div className="mt-6">
            <div className={`p-4 rounded-lg ${
              response.error ? "bg-red-900/50" : "bg-[#292B35]"
            }`}>
              {response.error ? (
                <div className="text-red-300 whitespace-pre-line">
                  <h3 className="font-bold text-lg mb-2">Error</h3>
                  <div className="font-mono text-sm">{response.error}</div>
                </div>
              ) : (
                <>
                  {activeTab === "extract" ? renderExtractionResults() : renderSearchResults()}
                </>
              )}
            </div>
          </div>
        )}

        <div className="mt-4 text-xs text-gray-500">
          <p className="font-semibold">Important Notes:</p>
          <ul className="list-disc list-inside space-y-1 mt-1">
            <li>Dark Web operations require active Tor connection</li>
            <li>Requests may take longer than normal web browsing</li>
            <li>Some sites may be unavailable or slow to respond</li>
            <li>Ensure your local Tor service is properly configured</li>
            <li>Exercise caution when visiting unknown .onion sites</li>
          </ul>
        </div>
      </div>
    </div>
  );
}