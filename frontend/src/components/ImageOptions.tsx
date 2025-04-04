import { useState } from "react";
import { X, Download, Search, Image as ImageIcon, Loader2, Code, ExternalLink, Check } from "lucide-react";

interface ImageOptionsProps {
  onClose: () => void;
  onSelectImage?: (imageUrl: string) => void;
}

interface DorkResult {
  title: string;
  link: string;
  favicon?: string;
}

interface DownloadProgress {
  [key: string]: number; // -1 = failed, 0-99 = in progress, 100 = completed
}

const API_BASE_URL = "http://127.0.0.1:8000";

export default function ImageOptions({ onClose, onSelectImage }: ImageOptionsProps) {
  const [images, setImages] = useState<string[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [selectedImages, setSelectedImages] = useState<string[]>([]);
  const [downloadProgress, setDownloadProgress] = useState<DownloadProgress>({});
  const [activeTab, setActiveTab] = useState<'image' | 'dork'>('image');
  const [dorkResults, setDorkResults] = useState<DorkResult[]>([]);
  const [searchSource, setSearchSource] = useState<'direct' | 'tor' | 'brave' | ''>('');

  const handleSearch = async () => {
    if (!query.trim()) {
      setError("Please enter a search query");
      return;
    }
    
    setError("");
    setLoading(true);
    
    // Add small delay to prevent rapid requests
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (activeTab === 'image') {
      setImages([]);
      setSelectedImages([]);
      await searchImages();
    } else {
      setDorkResults([]);
      setSearchSource('');
      await searchDorks();
    }
    
    setLoading(false);
  };

  const searchImages = async () => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/search-image/?keyword=${encodeURIComponent(query)}`
      );
      
      if (!response.ok) {
        throw new Error(response.statusText || "Search request failed");
      }

      const data = await response.json();
      if (!data.images || data.images.length === 0) {
        throw new Error("No images found for this query");
      }
      setImages(data.images || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
      console.error("Search error:", err);
    }
  };

const searchDorks = async () => {
    try {
      setError("");
      setLoading(true);
      
      const response = await fetch(
        `${API_BASE_URL}/api/dork-search/?dork=${encodeURIComponent(query)}&amount=10`
      );
      
      if (!response.ok) {
        throw new Error(response.statusText || "Search request failed");
      }

      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || "Search failed");
      }

      // Process results with favicons
      const processedResults = data.results.map((result: DorkResult) => {
        try {
          const url = new URL(result.link);
          return {
            ...result,
            favicon: `https://www.google.com/s2/favicons?domain=${url.hostname}`
          };
        } catch {
          return result;
        }
      });

      setDorkResults(processedResults);
      setSearchSource(data.source || 'direct');
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
      setDorkResults([]);
      console.error("Search error:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (url?: string) => {
    const urlsToDownload = url ? [url] : selectedImages.length ? selectedImages : images;
    
    if (urlsToDownload.length === 0) {
      setError("No images selected to download");
      return;
    }

    setLoading(true);
    setError("");
    
    // Initialize progress tracking
    const initialProgress: DownloadProgress = {};
    urlsToDownload.forEach(url => initialProgress[url] = 0);
    setDownloadProgress(initialProgress);

    try {
      for (const imgUrl of urlsToDownload) {
        try {
          const response = await fetch(`${API_BASE_URL}/api/download-single-image/`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: imgUrl }),
          });

          if (!response.ok) {
            throw new Error(`Failed to download ${imgUrl}`);
          }

          const reader = response.body?.getReader();
          if (!reader) throw new Error("Failed to read response body");

          const contentLength = +(response.headers.get('Content-Length') || '0');
          let receivedLength = 0;
          const chunks = [];

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            chunks.push(value);
            receivedLength += value.length;
            
            // Update progress
            const progress = Math.round((receivedLength / contentLength) * 100);
            setDownloadProgress(prev => ({
              ...prev,
              [imgUrl]: progress
            }));
          }

          const blob = new Blob(chunks);
          const downloadUrl = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = imgUrl.split('/').pop() || 'download';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          window.URL.revokeObjectURL(downloadUrl);

          // Mark download as complete
          setDownloadProgress(prev => ({
            ...prev,
            [imgUrl]: 100
          }));

        } catch (err) {
          console.error(`Error downloading ${imgUrl}:`, err);
          setDownloadProgress(prev => ({
            ...prev,
            [imgUrl]: -1 // Mark as failed
          }));
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Download failed");
      console.error("Download error:", err);
    } finally {
      setLoading(false);
    }
  };

  const toggleImageSelection = (url: string) => {
    setSelectedImages(prev => 
      prev.includes(url) 
        ? prev.filter(img => img !== url) 
        : [...prev, url]
    );
  };

  const sampleDorks = [
    { label: "PDFs", query: 'site:edu filetype:pdf' },
    { label: "Directories", query: 'intitle:"index of" "parent directory"' },
    { label: "WordPress", query: 'inurl:/wp-admin/admin-ajax.php' },
    { label: "Logins", query: 'intitle:"login" OR intitle:"sign in"' }
  ];

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
      <div className="bg-[#343541] rounded-lg p-6 w-[95%] max-w-4xl max-h-[90vh] overflow-y-auto relative">
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white transition-colors"
          disabled={loading}
        >
          <X className="w-6 h-6" />
        </button>

        <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          {activeTab === 'image' ? (
            <ImageIcon className="w-5 h-5" />
          ) : (
            <Code className="w-5 h-5" />
          )}
          {activeTab === 'image' ? 'Image Search' : 'Dork Search'}
        </h2>

        {/* Tab Selector */}
        <div className="flex mb-4 border-b border-gray-600">
          <button
            className={`px-4 py-2 font-medium ${activeTab === 'image' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-gray-400 hover:text-white'}`}
            onClick={() => setActiveTab('image')}
          >
            Image Search
          </button>
          <button
            className={`px-4 py-2 font-medium ${activeTab === 'dork' ? 'text-blue-400 border-b-2 border-blue-400' : 'text-gray-400 hover:text-white'}`}
            onClick={() => setActiveTab('dork')}
          >
            Dork Search
          </button>
        </div>

        <div className="relative mb-4">
          <input
            type="text"
            className="w-full p-3 pr-12 rounded-lg bg-[#40414F] text-white placeholder-gray-400"
            placeholder={
              activeTab === 'image' 
                ? "Search for images (e.g., cats, landscape, etc.)"
                : "Enter your dork query (e.g., 'site:example.com filetype:pdf')"
            }
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setError("");
            }}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            disabled={loading}
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              className="absolute right-14 top-3 text-gray-400 hover:text-white"
              disabled={loading}
            >
              <X className="w-5 h-5" />
            </button>
          )}
          {loading && (
            <div className="absolute right-4 top-3">
              <Loader2 className="w-5 h-5 animate-spin text-gray-400" />
            </div>
          )}
        </div>

        {error && (
          <div className="mb-4 p-3 bg-yellow-500/20 text-yellow-300 rounded-lg text-sm">
            {error}
          </div>
        )}

        {activeTab === 'dork' && !loading && (
          <div className="flex flex-wrap gap-2 mb-4">
            {sampleDorks.map((dork, index) => (
              <button
                key={index}
                onClick={() => setQuery(dork.query)}
                className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded"
              >
                {dork.label}
              </button>
            ))}
          </div>
        )}

        <div className="flex flex-wrap gap-3 mb-6">
          <button
            onClick={handleSearch}
            disabled={loading}
            className="flex-1 min-w-[150px] flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            {activeTab === 'image' ? 'Search Images' : 'Search Dorks'}
          </button>

          {activeTab === 'image' && (selectedImages.length > 0 || images.length > 0) && (
            <button
              onClick={() => handleDownload()}
              disabled={loading}
              className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg disabled:opacity-50"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
              {selectedImages.length > 0 
                ? `Download Selected (${selectedImages.length})`
                : "Download All"}
            </button>
          )}
        </div>

        {activeTab === 'image' ? (
          images.length > 0 ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
              {images.map((img, index) => (
                <div 
                  key={`img-${index}`} 
                  className={`relative group rounded-lg overflow-hidden bg-[#40414F] border-2 ${
                    selectedImages.includes(img) ? "border-blue-500" : "border-transparent"
                  }`}
                  onClick={() => toggleImageSelection(img)}
                >
                  <img
                    src={img}
                    alt={`${query} image ${index + 1}`}
                    className="w-full h-32 object-cover hover:opacity-80 transition-opacity cursor-pointer"
                    onError={(e) => {
                      (e.target as HTMLImageElement).style.display = "none";
                    }}
                  />
                  
                  {downloadProgress[img] !== undefined && (
                    <>
                      <div className="absolute top-2 right-2">
                        {downloadProgress[img] === 100 ? (
                          <Check className="w-4 h-4 text-green-500" />
                        ) : downloadProgress[img] === -1 ? (
                          <X className="w-4 h-4 text-red-500" />
                        ) : (
                          <Loader2 className="w-4 h-4 animate-spin text-blue-500" />
                        )}
                      </div>
                      <div className="absolute bottom-0 left-0 right-0 bg-gray-700 h-1">
                        {downloadProgress[img] >= 0 ? (
                          <div 
                            className={`h-1 transition-all duration-300 ${
                              downloadProgress[img] === 100 ? 'bg-green-500' : 'bg-blue-500'
                            }`}
                            style={{ width: `${downloadProgress[img]}%` }}
                          />
                        ) : (
                          <div className="h-1 bg-red-500 w-full" />
                        )}
                      </div>
                    </>
                  )}
                  
                  <div className="absolute inset-0 bg-gradient-to-t from-black/70 to-transparent opacity-0 group-hover:opacity-100 transition-opacity flex flex-col justify-between p-2">
                    {onSelectImage && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectImage(img);
                        }}
                        className="self-end bg-blue-600 hover:bg-blue-700 text-white p-1 rounded-full"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                      </button>
                    )}
                    <div className="flex justify-between items-end">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDownload(img);
                        }}
                        disabled={loading}
                        className="bg-purple-600 hover:bg-purple-700 text-white p-1 rounded-full"
                      >
                        <Download className="w-3 h-3" />
                      </button>
                      <span className="text-xs text-white bg-black/50 px-1 rounded truncate">
                        {img.startsWith('http') ? new URL(img).hostname : 'Local'}
                      </span>
                    </div>
                  </div>
                  {selectedImages.includes(img) && (
                    <div className="absolute top-1 left-1 bg-blue-500 rounded-full p-1">
                      <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-400">
              {loading ? (
                <div className="flex flex-col items-center">
                  <Loader2 className="w-8 h-8 mx-auto mb-2 animate-spin" />
                  <p>Searching for images...</p>
                </div>
              ) : (
                <>
                  <ImageIcon className="w-8 h-8 mx-auto mb-2" />
                  <p>Enter a search term and click "Search Images" to find related images</p>
                  <p className="text-sm mt-2">Example searches: "sunset", "mountain landscape", "cute cats"</p>
                </>
              )}
            </div>
          )
        ) : (
          dorkResults.length > 0 ? (
            <div className="space-y-3">
              {searchSource && (
                <div className="text-sm text-gray-400">
                  Results from: {searchSource === 'direct' ? 'Standard search' : 
                                searchSource === 'brave' ? 'Brave' : 'Tor network'}
                </div>
              )}
              {dorkResults.map((result, index) => (
                <div
                  key={index}
                  className="p-3 bg-[#40414F] rounded-lg hover:bg-[#4E4F5A] transition-colors"
                >
                  <a
                    href={result.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-start gap-2 group"
                  >
                    {result.favicon && (
                      <img 
                        src={result.favicon} 
                        alt="favicon" 
                        className="w-4 h-4 mt-1" 
                        onError={(e) => {
                          (e.target as HTMLImageElement).style.display = 'none';
                        }}
                      />
                    )}
                    <div className="flex-1 min-w-0">
                      <h3 className="text-white group-hover:text-blue-400 line-clamp-1">
                        {result.title || 'No title available'}
                      </h3>
                      <p className="text-xs text-gray-400 mt-1 truncate">
                        {result.link}
                      </p>
                    </div>
                    <ExternalLink className="w-4 h-4 text-gray-400 group-hover:text-blue-400" />
                  </a>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-400">
              {loading ? (
                <div className="flex flex-col items-center">
                  <Loader2 className="w-8 h-8 mx-auto mb-2 animate-spin" />
                  <p>Searching for dorks...</p>
                </div>
              ) : (
                <>
                  <Code className="w-8 h-8 mx-auto mb-2" />
                  <p>No results found for your search</p>
                  <p className="text-sm mt-2">Try a different query or check your search terms</p>
                </>
              )}
            </div>
          )
        )}
      </div>
    </div>
  );
}