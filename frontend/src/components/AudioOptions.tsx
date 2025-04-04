import { X, Play, Pause, Save, Loader2, Type } from "lucide-react";
import { useState, useRef, useEffect } from "react";

interface AudioOptionsProps {
  onClose: () => void;
}

export default function AudioOptions({ onClose }: AudioOptionsProps) {
  // State management
  const [activeOption, setActiveOption] = useState<"upload" | "text" | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    transcription?: string;
    translation?: string;
  } | null>(null);
  const [audioBlob, setAudioBlob] = useState<Blob | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [targetLanguage, setTargetLanguage] = useState("hi"); // Default to Hindi
  const [textToTranslate, setTextToTranslate] = useState("");

  // Refs
  const audioRef = useRef<HTMLAudioElement | null>(null);

  // Supported languages
  const languages = [
    { code: "hi", name: "Hindi" },
    { code: "es", name: "Spanish" },
    { code: "fr", name: "French" },
    { code: "de", name: "German" },
    { code: "ja", name: "Japanese" },
    { code: "en", name: "English" },
    { code: "zh", name: "Chinese" },
  ];

  // Clean up effects
  useEffect(() => {
    return () => {
      if (audioUrl) URL.revokeObjectURL(audioUrl);
    };
  }, [audioUrl]);

  // Play/pause recorded audio
  const togglePlayPause = () => {
    if (audioRef.current) {
      if (isPlaying) {
        audioRef.current.pause();
      } else {
        audioRef.current.play();
      }
      setIsPlaying(!isPlaying);
    }
  };

  // Save audio file
  const saveAudio = () => {
    if (audioBlob) {
      const url = URL.createObjectURL(audioBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `audio_${new Date().toISOString().slice(0, 10)}.wav`;
      a.click();
    }
  };

  // Process audio for translation
  const processAudio = async () => {
    if (!audioBlob && activeOption !== "text") {
      setResult({ translation: "No audio to process" });
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      if (activeOption === "text") {
        // Handle text translation
        const response = await fetch("http://127.0.0.1:8000/api/translate-text/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: textToTranslate,
            target_language: targetLanguage
          }),
        });

        if (!response.ok) throw new Error("Failed to translate text");
        
        const data = await response.json();
        setResult({
          translation: data.translation,
        });
      } else {
        // Handle audio translation
        const formData = new FormData();
        formData.append("audio_file", audioBlob!, "audio.wav");
        formData.append("target_language", targetLanguage);

        const response = await fetch("http://127.0.0.1:8000/api/audio-process/", {
          method: "POST",
          body: formData,
        });

        if (!response.ok) throw new Error("Failed to process audio");

        const data = await response.json();
        setResult({
          transcription: data.transcription,
          translation: data.translation,
        });
      }
    } catch (error) {
      console.error("Error processing request:", error);
      setResult({ translation: "Error processing request. Please try again." });
    } finally {
      setLoading(false);
    }
  };

  // Reset to main menu
  const resetToMainMenu = () => {
    setActiveOption(null);
    setAudioBlob(null);
    setAudioUrl(null);
    setResult(null);
    setTextToTranslate("");
    setIsPlaying(false);
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.currentTime = 0;
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-[#343541] rounded-lg p-6 w-full max-w-md relative">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white"
        >
          <X className="w-6 h-6" />
        </button>

        <h2 className="text-xl text-white font-semibold mb-4">
          {activeOption === null ? "Translation Options" : 
           activeOption === "text" ? "Translate Text" : "Translate Audio"}
        </h2>

        {activeOption === null ? (
          // Main menu view
          <div className="space-y-3">
            <button
              className="w-full bg-[#40414F] hover:bg-[#4a4b59] text-white p-4 rounded-lg flex items-center gap-3 transition-colors"
              onClick={() => {
                const input = document.createElement("input");
                input.type = "file";
                input.accept = "audio/*";
                input.onchange = (e) => {
                  const file = (e.target as HTMLInputElement).files?.[0];
                  if (file) {
                    setAudioBlob(file);
                    setAudioUrl(URL.createObjectURL(file));
                    setActiveOption("upload");
                  }
                };
                input.click();
              }}
            >
              <Play className="w-5 h-5" />
              <span>Upload Audio File</span>
            </button>
            <button
              className="w-full bg-[#40414F] hover:bg-[#4a4b59] text-white p-4 rounded-lg flex items-center gap-3 transition-colors"
              onClick={() => setActiveOption("text")}
            >
              <Type className="w-5 h-5" />
              <span>Translate Text</span>
            </button>
          </div>
        ) : activeOption === "text" ? (
          // Text translation view
          <div className="space-y-4">
            <div className="flex flex-col gap-2">
              <label className="text-white text-sm">Text to translate:</label>
              <textarea
                value={textToTranslate}
                onChange={(e) => setTextToTranslate(e.target.value)}
                className="w-full bg-[#40414F] text-white p-3 rounded border border-[#555766] min-h-[100px]"
                placeholder="Enter text to translate..."
              />
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-white text-sm">Translate to:</label>
              <select
                value={targetLanguage}
                onChange={(e) => setTargetLanguage(e.target.value)}
                className="w-full bg-[#40414F] text-white p-2 rounded border border-[#555766]"
              >
                {languages.map((lang) => (
                  <option key={lang.code} value={lang.code}>
                    {lang.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex gap-3">
              <button
                onClick={processAudio}
                disabled={!textToTranslate.trim() || loading}
                className={`flex-1 bg-green-500 hover:bg-green-600 text-white py-2 px-4 rounded-lg flex items-center justify-center gap-2 ${
                  !textToTranslate.trim() || loading ? "opacity-70" : ""
                }`}
              >
                {loading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <>
                    <Type className="w-5 h-5" />
                    Translate
                  </>
                )}
              </button>
              <button
                onClick={resetToMainMenu}
                className="flex-1 bg-gray-500 hover:bg-gray-600 text-white py-2 px-4 rounded-lg"
              >
                Cancel
              </button>
            </div>

            {/* Results display */}
            {result?.translation && (
              <div className="mt-4 bg-[#40414F] p-3 rounded-lg">
                <h3 className="text-white font-medium mb-1">Translation:</h3>
                <p className="text-green-400">{result.translation}</p>
              </div>
            )}
          </div>
        ) : (
          // Audio translation view (upload only)
          <div className="space-y-4">
            {/* Audio playback controls */}
            {audioUrl && (
              <div className="flex items-center justify-between bg-[#40414F] p-3 rounded-lg">
                <div className="flex items-center gap-3">
                  <button
                    onClick={togglePlayPause}
                    className="p-2 bg-green-500 hover:bg-green-600 text-white rounded-full"
                  >
                    {isPlaying ? (
                      <Pause className="w-5 h-5" />
                    ) : (
                      <Play className="w-5 h-5" />
                    )}
                  </button>
                  <span className="text-white">Uploaded Audio</span>
                </div>
                <button
                  onClick={saveAudio}
                  className="p-2 bg-blue-500 hover:bg-blue-600 text-white rounded-full"
                >
                  <Save className="w-5 h-5" />
                </button>
                <audio
                  ref={audioRef}
                  src={audioUrl}
                  onEnded={() => setIsPlaying(false)}
                  hidden
                />
              </div>
            )}

            {/* Language selection */}
            <div className="space-y-2">
              <label className="text-white text-sm">Translate to:</label>
              <select
                value={targetLanguage}
                onChange={(e) => setTargetLanguage(e.target.value)}
                className="w-full bg-[#40414F] text-white p-2 rounded border border-[#555766]"
              >
                {languages.map((lang) => (
                  <option key={lang.code} value={lang.code}>
                    {lang.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Action buttons */}
            <div className="flex gap-3">
              <button
                onClick={processAudio}
                disabled={loading || !audioBlob}
                className={`flex-1 bg-green-500 hover:bg-green-600 text-white py-2 px-4 rounded-lg flex items-center justify-center gap-2 ${
                  loading || !audioBlob ? "opacity-70" : ""
                }`}
              >
                {loading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    Translate
                  </>
                )}
              </button>
              <button
                onClick={resetToMainMenu}
                className="flex-1 bg-gray-500 hover:bg-gray-600 text-white py-2 px-4 rounded-lg"
              >
                Back
              </button>
            </div>

            {/* Results display */}
            {result && (
              <div className="mt-4 space-y-3">
                {result.transcription && (
                  <div className="bg-[#40414F] p-3 rounded-lg">
                    <h3 className="text-white font-medium mb-1">Transcription:</h3>
                    <p className="text-gray-300">{result.transcription}</p>
                  </div>
                )}
                {result.translation && (
                  <div className="bg-[#40414F] p-3 rounded-lg">
                    <h3 className="text-white font-medium mb-1">Translation:</h3>
                    <p className="text-green-400">{result.translation}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}