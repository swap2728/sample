import { useState } from 'react';
import { FileText, Image as ImageIcon, Mic, ChevronDown, ChevronUp, Lock, Zap } from 'lucide-react';

type InstructionsPopupProps = {
  onClose: () => void;
};

export function InstructionsPopup({ onClose }: InstructionsPopupProps) {
  const [expandedSection, setExpandedSection] = useState<string | null>(null);

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
      <div className="bg-[#444654] rounded-lg p-6 text-white w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-4 sticky top-0 bg-[#444654] py-2">
          <h2 className="text-xl font-bold">Instruction Manual</h2>
          <button 
            onClick={onClose}
            className="p-1 rounded-full hover:bg-gray-700"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="space-y-2">
          {/* Text Options Section */}
          <div className="border border-gray-600 rounded-lg overflow-hidden">
            <button
              className="w-full flex justify-between items-center p-4 hover:bg-[#40414F]"
              onClick={() => toggleSection('text')}
            >
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                <span className="font-semibold">Text Options</span>
              </div>
              {expandedSection === 'text' ? <ChevronUp /> : <ChevronDown />}
            </button>
            
            {expandedSection === 'text' && (
              <div className="p-4 pt-0 bg-[#40414F]">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium">System Info / System Data</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>No input required</li>
                      <li>Immediately fetches and displays system information</li>
                      <li>System Info shows condensed data</li>
                      <li>System Data shows expanded details</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">File Data</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click the option</li>
                      <li>A prompt appears asking for a file/directory path</li>
                      <li>Enter a valid path and click OK</li>
                      <li>The component will display file/directory analysis</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Nmap Scan</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click the option</li>
                      <li>An input field appears for the target IP/domain</li>
                      <li>Enter the target (e.g., "192.168.1.1" or "example.com")</li>
                      <li>Press Enter or click the option again to execute</li>
                      <li>Results will show open ports and services</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">AES Encryption</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click the option</li>
                      <li>A prompt asks to choose encryption or decryption</li>
                      <li>Select 1 (encrypt) or 2 (decrypt)</li>
                      <li>Enter the text to process</li>
                      <li>Enter the encryption key</li>
                      <li>Results will show the processed text</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Capture Packets</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click the option</li>
                      <li>The component fetches available network interfaces</li>
                      <li>Select an interface from the prompt</li>
                      <li>Enter number of packets to capture (1-100)</li>
                      <li>Results show a table of captured packets with timestamp, source IP, destination IP, protocol, and packet info</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Vulnerability Scan</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click the option</li>
                      <li>An input field appears for the target IP/domain</li>
                      <li>Enter the target</li>
                      <li>Press Enter or click the option again to execute</li>
                      <li>Results show security grade, list of vulnerabilities, and scan configuration details</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">DuckDuckGo Search</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click the option</li>
                      <li>An input field appears for the search query</li>
                      <li>Enter your search terms</li>
                      <li>Press Enter or click the option again to execute</li>
                      <li>Results show up to 20 search results with titles and URLs</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Image Search Section */}
          <div className="border border-gray-600 rounded-lg overflow-hidden">
            <button
              className="w-full flex justify-between items-center p-4 hover:bg-[#40414F]"
              onClick={() => toggleSection('image')}
            >
              <div className="flex items-center gap-2">
                <ImageIcon className="w-5 h-5" />
                <span className="font-semibold">Image Search</span>
              </div>
              {expandedSection === 'image' ? <ChevronUp /> : <ChevronDown />}
            </button>
            
            {expandedSection === 'image' && (
              <div className="p-4 pt-0 bg-[#40414F]">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium">Searching for Images:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Ensure the "Image Search" tab is selected</li>
                      <li>Enter your search query (e.g., "cats", "landscape")</li>
                      <li>Click "Search Images" or press Enter</li>
                      <li>View results in a grid format</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Image Operations:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click an image to select it (blue border indicates selection)</li>
                      <li>Click the download icon on an image to download just that image</li>
                      <li>Use "Download Selected" to download multiple selected images</li>
                      <li>Use "Download All" to download all found images</li>
                      <li>If onSelectImage prop is provided, use the checkmark icon to select an image</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Batch Operations:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Select multiple images by clicking them</li>
                      <li>Download all selected images at once</li>
                      <li>Clear selections by clicking selected images again</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Dork Search Functionality:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Select the "Dork Search" tab</li>
                      <li>Enter your dork query (e.g., "site:edu filetype:pdf")</li>
                      <li>Click "Search Dorks" or press Enter</li>
                      <li>View results as a list of links</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Sample Dorks:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>PDFs: Finds PDF documents on .edu sites</li>
                      <li>Directories: Finds open directory listings</li>
                      <li>WordPress: Finds WordPress admin pages</li>
                      <li>Logins: Finds login pages</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Dork Result Features:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Each result shows page title (truncated if long), URL (with domain highlighted), favicon when available, and external link icon</li>
                      <li>Click any result to open in new tab</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Audio Options Section */}
          <div className="border border-gray-600 rounded-lg overflow-hidden">
            <button
              className="w-full flex justify-between items-center p-4 hover:bg-[#40414F]"
              onClick={() => toggleSection('audio')}
            >
              <div className="flex items-center gap-2">
                <Mic className="w-5 h-5" />
                <span className="font-semibold">Audio Options</span>
              </div>
              {expandedSection === 'audio' ? <ChevronUp /> : <ChevronDown />}
            </button>
            
            {expandedSection === 'audio' && (
              <div className="p-4 pt-0 bg-[#40414F]">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium">Upload Audio File:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Click to open file picker</li>
                      <li>Select any audio file</li>
                      <li>File will be prepared for translation</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Translate Text:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Switch to text translation mode</li>
                      <li>Enter text directly for translation</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Text Translation:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Enter text in the textarea</li>
                      <li>Select target language</li>
                      <li>Click "Translate" button</li>
                      <li>View translation result below</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Language Selection:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Supported languages: Hindi (hi), Spanish (es), French (fr), German (de), Japanese (ja), English (en), Chinese (zh)</li>
                      <li>Default is Hindi</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Dark Web Operations Section */}
          <div className="border border-gray-600 rounded-lg overflow-hidden">
            <button
              className="w-full flex justify-between items-center p-4 hover:bg-[#40414F]"
              onClick={() => toggleSection('darkweb')}
            >
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5" />
                <span className="font-semibold">Dark Web Operations</span>
              </div>
              {expandedSection === 'darkweb' ? <ChevronUp /> : <ChevronDown />}
            </button>
            
            {expandedSection === 'darkweb' && (
              <div className="p-4 pt-0 bg-[#40414F]">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium">Tor Connection</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>The component automatically checks Tor status on load</li>
                      <li>If connection fails:</li>
                      <ul className="list-disc pl-5 space-y-1 mt-1">
                        <li>Ensure Tor Browser is running or your system Tor service is active</li>
                        <li>Verify no firewall is blocking connections</li>
                        <li>Check backend service is running</li>
                      </ul>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Extracting Data from .onion Sites</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Select the "Extract Data" tab</li>
                      <li>Enter a valid .onion URL (e.g., http://example.onion)</li>
                      <li>Click "Extract Data" button</li>
                      <li>Wait for processing (may take longer than normal web requests)</li>
                      <li>View extracted information including:</li>
                      <ul className="list-disc pl-5 space-y-1 mt-1">
                        <li>Page metadata (title, URL, stats)</li>
                        <li>Headers structure</li>
                        <li>Security indicators</li>
                        <li>Sensitive information found</li>
                        <li>Bitcoin addresses, emails, phone numbers</li>
                      </ul>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Searching the Dark Web</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Select the "Search Dark Web" tab</li>
                      <li>Enter your search keywords (e.g., "marketplace", "forum", "leaks")</li>
                      <li>Click "Search Dark Web" button</li>
                      <li>View results showing:</li>
                      <ul className="list-disc pl-5 space-y-1 mt-1">
                        <li>Site titles and descriptions</li>
                        <li>Categories and types</li>
                        <li>Direct links to dark web sites</li>
                      </ul>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Zero Day Exploit Section */}
          <div className="border border-gray-600 rounded-lg overflow-hidden">
            <button
              className="w-full flex justify-between items-center p-4 hover:bg-[#40414F]"
              onClick={() => toggleSection('zeroday')}
            >
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5" />
                <span className="font-semibold">Zero Day Exploit</span>
              </div>
              {expandedSection === 'zeroday' ? <ChevronUp /> : <ChevronDown />}
            </button>
            
            {expandedSection === 'zeroday' && (
              <div className="p-4 pt-0 bg-[#40414F]">
                <div className="space-y-4">
                  <div>
                    <h4 className="font-medium">Initial State:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Shows an input field for the target IP address</li>
                      <li>Has a "Initiate Zero Day Scan" button</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Scanning Process:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>Enter the target IP address in the input field</li>
                      <li>Click "Initiate Zero Day Scan" button</li>
                      <li>The interface shows a loading state during scanning</li>
                      <li>On success, displays detailed information about the target</li>
                      <li>On error, shows an error message with details</li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Results Display:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>
                        <strong>Network Information:</strong>
                        <ul className="list-disc pl-5 mt-1">
                          <li>Hostname</li>
                          <li>ISP (Internet Service Provider)</li>
                          <li>Organization</li>
                          <li>ASN (Autonomous System Number)</li>
                        </ul>
                      </li>
                      <li>
                        <strong>Geolocation Data:</strong>
                        <ul className="list-disc pl-5 mt-1">
                          <li>City</li>
                          <li>Region</li>
                          <li>Country</li>
                          <li>Coordinates (latitude and longitude)</li>
                        </ul>
                      </li>
                      <li>
                        <strong>DNS Records:</strong>
                        <ul className="list-disc pl-5 mt-1">
                          <li>MX (Mail Exchange) records</li>
                          <li>NS (Name Server) records</li>
                        </ul>
                      </li>
                      <li>
                        <strong>WHOIS Information:</strong>
                        <ul className="list-disc pl-5 mt-1">
                          <li>Registrar details</li>
                          <li>Domain creation date</li>
                          <li>Expiration date</li>
                          <li>Last updated date</li>
                        </ul>
                      </li>
                      <li>
                        <strong>Open Ports Table:</strong>
                        <ul className="list-disc pl-5 mt-1">
                          <li>Port number</li>
                          <li>Service running on the port</li>
                          <li>Service version</li>
                          <li>Port state (open/filtered/closed)</li>
                        </ul>
                      </li>
                      <li>
                        <strong>Vulnerability List:</strong>
                        <ul className="list-disc pl-5 mt-1">
                          <li>List of identified vulnerabilities</li>
                          <li>Severity indicators (color-coded: critical, high, medium, low)</li>
                          <li>Vulnerability descriptions</li>
                          <li>Potential impact</li>
                          <li>Suggested remediation</li>
                        </ul>
                      </li>
                    </ul>
                  </div>

                  <div>
                    <h4 className="font-medium">Important Notes:</h4>
                    <ul className="list-disc pl-5 space-y-1 mt-1 text-sm">
                      <li>This tool should only be used on systems you own or have permission to scan</li>
                      <li>Scanning without authorization may be illegal in your jurisdiction</li>
                      <li>Results may contain sensitive information - handle with care</li>
                      <li>Some information may be redacted for security reasons</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}