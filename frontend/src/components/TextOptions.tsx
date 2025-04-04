import { X } from 'lucide-react';
import { useState, useEffect } from 'react';

interface TextOptionsProps {
  onClose: () => void;
  onSelectOption: (option: string, response: string) => void;
}

const API_BASE_URL = 'http://127.0.0.1:8000/api';

export default function TextOptions({ onClose, onSelectOption }: TextOptionsProps) {
  const options = [
    "System Info",
    "System Data",
    "File Data",
    "Nmap scan",
    "AES Encryption",
    "Capture Packets",
    "Vulnerability Scan",
    "DuckDuckGo Search"
  ];

  const [loading, setLoading] = useState<string | null>(null);
  const [inputValue, setInputValue] = useState('');
  const [error, setError] = useState('');
  const [activeOption, setActiveOption] = useState<string | null>(null);
  const [showInput, setShowInput] = useState(false);

  const needsInput = (option: string): boolean => {
    return [
      "Nmap scan",
      "Vulnerability Scan",
      "DuckDuckGo Search"
    ].includes(option);
  };

  useEffect(() => {
    if (activeOption && needsInput(activeOption)) {
      setShowInput(true);
      setInputValue('');
      setError('');
    } else {
      setShowInput(false);
    }
  }, [activeOption]);

  const handleOptionClick = (option: string) => {
    if (loading) return;

    if (activeOption === option && showInput && inputValue.trim()) {
      handleSelect(option);
    } else {
      setActiveOption(option);
      if (!needsInput(option)) {
        handleSelect(option);
      }
    }
  };

  const handleSelect = async (option: string) => {
    if (needsInput(option) && !inputValue.trim()) {
      setError("Target is required");
      return;
    }

    setLoading(option);

    try {
      let responseText = '';
      
      switch (option) {
        case "System Info":
        case "System Data":
          responseText = await handleSystemInfo(option);
          break;
        
        case "File Data":
          responseText = await handleFileData();
          break;
        
        case "Nmap scan":
          responseText = await handleNmapScan();
          break;
        
        case "AES Encryption":
          responseText = await handleAESEncryption();
          break;
        
        case "Capture Packets":
          responseText = await handlePacketCapture();
          break;
        
        case "Vulnerability Scan":
          responseText = await handleVulnerabilityScan();
          break;
        
        case "DuckDuckGo Search":
          responseText = await handleDuckDuckGoSearch();
          break;
        
        default:
          responseText = `Received ${option} request`;
      }

      onSelectOption(option, responseText);
      onClose();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Request failed';
      setError(errorMessage);
    } finally {
      setLoading(null);
    }
  };

  const handleSystemInfo = async (option: string): Promise<string> => {
    const response = await fetch(`${API_BASE_URL}/system-info/`);
    if (!response.ok) {
      throw new Error(`Request failed with status ${response.status}`);
    }
    const data = await response.json();

    if (option === "System Info") {
      return `System Information:
- OS: ${data.System}
- Hostname: ${data["Node Name"]}
- IP Address: ${data["IP Address"]}
- Other IPs: ${data["All IPs"].join(', ')}
- Release: ${data.Release}
- Version: ${data.Version}
- CPU Cores: ${data["Physical Cores"]} (${data["Total Cores"]} threads)
- Memory: ${data.Memory}`;
    } else {
      return `Detailed System Data:
Operating System:
- Name: ${data.System}
- Version: ${data.Version}
- Release: ${data.Release}

Network Information:
- Hostname: ${data["Node Name"]}
- Primary IP: ${data["IP Address"]}
- All IPs: ${data["All IPs"].join('\n  ')}

Hardware Information:
- Machine: ${data.Machine}
- Processor: ${data.Processor}
- Physical Cores: ${data["Physical Cores"]}
- Logical Cores: ${data["Total Cores"]}
- CPU Frequency: ${data["Max Frequency"]}

Memory:
- Total: ${data.Memory}`;
    }
  };

  const handleFileData = async (): Promise<string> => {
    const path = prompt("Enter file or directory path:");
    if (!path) {
      throw new Error("No path provided");
    }

    const response = await fetch(`${API_BASE_URL}/file-data/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ path })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Request failed with status ${response.status}`);
    }

    const data = await response.json();
    
    if (data.type === 'file') {
      return `File Analysis:
- Path: ${data.path}
- Name: ${data.name}
- Size: ${data.size_human}
- Type: ${data.extension}
- Permissions: ${data.permissions}
- Created: ${data.created}
- Modified: ${data.modified}
${data.content_sample ? `\nContent Sample:\n${data.content_sample}` : ''}`;
    } else {
      return `Directory Analysis:
- Path: ${data.path}
- Total Files: ${data.file_count}
- Total Subdirectories: ${data.dir_count}
- Total Size: ${data.total_size_human}
- Permissions: ${data.permissions}
- Created: ${data.created}
- Modified: ${data.modified}

File Types: ${Object.entries(data.files_by_type)
        .map(([ext, count]) => `${ext}: ${count}`)
        .join(', ')}

Sample Files:
${data.files.slice(0, 10)
        .map((f: any) => `${f.name} (${f.size_human})`)
        .join('\n')}`;
    }
  };

  const handleNmapScan = async (): Promise<string> => {
    const target = inputValue.trim();
    if (!target) throw new Error("Target IP or domain is required");
  
    const response = await fetch(`${API_BASE_URL}/text-option/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ option: "Nmap scan", target })
    });
  
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Scan failed with status ${response.status}`);
    }
  
    const data = await response.json();
    
    if (data.scan_results?.open_ports) {
      // Format the results in Nmap-style output
      let result = `Nmap scan results for ${target}:\n\n`;
      result += "PORT     STATE    SERVICE\n";
      
      data.scan_results.open_ports.forEach((portInfo: {
        port: number,
        service: string,
        state: string
      }) => {
        result += `${portInfo.port.toString().padEnd(8)} ${portInfo.state.padEnd(8)} ${portInfo.service}\n`;
      });
      
      return result;
    }
    
    return "Scan completed but no open ports found";
  };

  const handleAESEncryption = async (): Promise<string> => {
    const action = prompt("Choose action:\n1. Encrypt\n2. Decrypt", "1");
    if (!action) return "Operation cancelled";
    
    const text = prompt("Enter the text:");
    if (!text) return "Text is required";
    
    const key = prompt("Enter encryption key:");
    if (!key) return "Key is required";
    
    const response = await fetch(`${API_BASE_URL}/aes-encryption/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        action: action === "1" ? "encrypt" : "decrypt",
        text: text,
        key: key
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Request failed with status ${response.status}`);
    }

    const data = await response.json();
    return `${action === "1" ? "Encrypted" : "Decrypted"} text:\n${data.result}`;
  };

  const handlePacketCapture = async (): Promise<string> => {
    try {
      // Get available interfaces
      const interfacesRes = await fetch(`${API_BASE_URL}/capture-packets/`);
      if (!interfacesRes.ok) {
        throw new Error(`Failed to get interfaces: ${interfacesRes.status}`);
      }
  
      const interfacesData = await interfacesRes.json();
      if (interfacesData.status !== "success") {
        throw new Error(interfacesData.error || 'Failed to get interfaces');
      }
  
      const availableInterfaces = interfacesData.available_interfaces || ["eth0"];
      if (availableInterfaces.length === 0) {
        throw new Error('No network interfaces found');
      }
  
      // Prompt user for interface selection
      const interfaceName = prompt(
        `Available interfaces:\n${availableInterfaces.join('\n')}\n\nSelect interface:`,
        availableInterfaces[0]
      );
      
      if (!interfaceName) {
        throw new Error('No interface selected');
      }
  
      // Get packet count
      let count = 10;
      try {
        const countInput = prompt("Packets to capture (1-100):", "10") || "10";
        count = Math.min(Math.max(parseInt(countInput), 1), 100);
      } catch {
        throw new Error('Invalid packet count. Using default 10.');
      }
  
      // Start capture
      const formData = new FormData();
      formData.append('interface', interfaceName);
      formData.append('count', count.toString());
  
      const response = await fetch(`${API_BASE_URL}/capture-packets/`, {
        method: 'POST',
        body: formData
      });
  
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Capture failed with status ${response.status}`);
      }
  
      const data = await response.json();
      if (data.status !== "success") {
        throw new Error(data.error || 'Capture failed');
      }
  
      // Format results
      if (!data.packets || data.packets.length === 0) {
        return `No packets captured on interface ${interfaceName}`;
      }
  
      let result = `📡 Packet Capture Results (${data.packets.length} packets)\n`;
      result += `Interface: ${interfaceName}\n`;
      result += "┌──────────┬─────────────────┬─────────────────┬──────────┬───────────────────┐\n";
      result += "│ Time     │ Source          │ Destination     │ Protocol │ Info              │\n";
      result += "├──────────┼─────────────────┼─────────────────┼──────────┼───────────────────┤\n";
      
      data.packets.forEach((pkt: any, index: number) => {
        result += `│ ${pkt.time?.padEnd(8) || 'N/A'.padEnd(8)} │ ${
          (pkt.source?.slice(0, 15) || 'N/A').padEnd(15)} │ ${
          (pkt.destination?.slice(0, 15) || 'N/A').padEnd(15)} │ ${
          (pkt.protocol?.padEnd(8) || 'UNKNOWN')} │ ${
          (pkt.info?.slice(0, 18) || 'N/A').padEnd(18)} │\n`;
      });
      
      result += "└──────────┴─────────────────┴─────────────────┴──────────┴───────────────────┘\n";
      
      // Add statistics
      const protocols: Record<string, number> = {};
      data.packets.forEach((pkt: any) => {
        const proto = pkt.protocol || 'UNKNOWN';
        protocols[proto] = (protocols[proto] || 0) + 1;
      });
      
      result += "\nProtocol Statistics:\n";
      Object.entries(protocols).forEach(([proto, count]) => {
        result += `- ${proto}: ${count} packets\n`;
      });
  
      return result;
  
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Packet capture failed';
      return `❌ Error capturing packets:\n${errorMessage}\n\nPlease check:\n1. You have proper permissions\n2. The interface exists\n3. Scapy is installed (pip install scapy)`;
    }
  };

  const handleVulnerabilityScan = async (): Promise<string> => {
    const target = inputValue.trim();
    if (!target) {
      throw new Error("Target IP or domain is required");
    }
  
    try {
      const response = await fetch(`${API_BASE_URL}/vulnerability-scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ target }),
      });
  
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Scan failed with status ${response.status}`);
      }
  
      const data = await response.json();
      
      if (!data.results) {
        throw new Error("Invalid scan results format");
      }
  
      // Format the results
      let result = `🔍 Vulnerability Scan Report for ${data.results.target}\n\n`;
      result += `📊 Security Grade: ${data.results.security_grade}\n\n`;
  
      // Vulnerabilities section
      if (data.results.vulnerabilities?.length > 0) {
        result += `⚠️ Found ${data.results.vulnerabilities.length} vulnerabilities:\n\n`;
        result += data.results.vulnerabilities.map((vuln: string, i: number) => 
          `${i + 1}. ${vuln}`
        ).join('\n\n');
      } else {
        result += "✅ No vulnerabilities detected\n";
      }
  
      // Add scan metadata
      result += `\n---\nScan mode: ${data.scan_config.safe_mode ? 'Safe' : 'Aggressive'}`;
      result += ` | Tests performed: ${data.scan_config.tests_performed}`;
  
      return result;
  
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Scan failed';
      throw new Error(`Vulnerability scan error: ${errorMessage}`);
    }
  };

  const handleDuckDuckGoSearch = async (): Promise<string> => {
    const response = await fetch(`${API_BASE_URL}/duckduckgo-search/?query=${encodeURIComponent(inputValue)}`);
    if (!response.ok) {
      throw new Error(`Request failed with status ${response.status}`);
    }

    const results = await response.json();
    if (!results || results.length === 0) {
      return `No results found for: ${inputValue}`;
    }

    return `Search results for "${inputValue}":\n\n${
      results.slice(0, 20).map((r: any, i: number) => 
        `${i+1}. ${r.title}\n   ${r.link}`
      ).join('\n\n')
    }`;
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-[#343541] rounded-lg p-6 w-[400px] relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white"
          disabled={!!loading}
        >
          <X className="w-6 h-6" />
        </button>

        <h2 className="text-xl text-white font-semibold mb-4">Text Options</h2>

        {showInput && (
          <div className="mb-3">
            <input
              type="text"
              placeholder={
                activeOption === "Nmap scan" || activeOption === "Vulnerability Scan"
                  ? "Enter target IP or domain"
                  : "Enter search query"
              }
              value={inputValue}
              onChange={(e) => {
                setInputValue(e.target.value);
                setError('');
              }}
              className="w-full p-2 rounded-lg bg-[#40414F] text-white"
              disabled={!!loading}
              onKeyDown={(e) => e.key === 'Enter' && handleSelect(activeOption!)}
              autoFocus
            />
            {error && (
              <p className="text-red-400 text-sm mt-1">{error}</p>
            )}
          </div>
        )}

        <div className="space-y-2">
          {options.map((option) => (
            <button
              key={option}
              className={`w-full bg-[#40414F] text-white p-3 rounded-lg hover:bg-[#4a4b59] transition-colors text-left ${
                loading === option ? 'opacity-70' : ''
              } ${
                activeOption === option ? 'ring-2 ring-blue-500' : ''
              }`}
              onClick={() => handleOptionClick(option)}
              disabled={!!loading && loading !== option}
            >
              <div className="flex items-center justify-between">
                <span>{option}</span>
                {loading === option ? (
                  <span className="animate-spin">↻</span>
                ) : activeOption === option && needsInput(option) ? (
                  <span>⏎</span>
                ) : null}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}