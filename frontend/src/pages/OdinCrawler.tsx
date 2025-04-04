import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

interface CrawlerResults {
  title?: string;
  text_content?: string;
  images?: string[];
  links?: string[];
}

interface UserStatus {
  hasAccess: boolean;
  isTrial: boolean;
  trialEnds?: string;
  status?: string;
  reason?: string;
  message?: string;
}

const OdinCrawler: React.FC = () => {
  const navigate = useNavigate();
  const [keyword, setKeyword] = useState("");
  const [url, setUrl] = useState("");
  const [results, setResults] = useState<CrawlerResults | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [processingSubscription, setProcessingSubscription] = useState(false);
  const [userStatus, setUserStatus] = useState<UserStatus>({
    hasAccess: false,
    isTrial: false,
  });
  const [showWelcome, setShowWelcome] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);

  // Generate user id if not exists
  useEffect(() => {
    if (!localStorage.getItem("user_id")) {
      const newUserId = Date.now();
      localStorage.setItem("user_id", newUserId.toString());
    }
  }, []);

  // Check user access status
  useEffect(() => {
    const checkAccess = async () => {
      try {
        const userId = localStorage.getItem("user_id");
        if (!userId) return;

        const response = await fetch(
          `http://127.0.0.1:8000/api/crawl/check-access/?user_id=${userId}`
        );
        const data = await response.json();
        
        setUserStatus({
          hasAccess: data.access,
          isTrial: data.is_trial,
          trialEnds: data.trial_ends,
          status: data.status,
          reason: data.reason,
          message: data.message
        });

        if (data.access && !data.is_trial) {
          setShowWelcome(true);
          setTimeout(() => setShowWelcome(false), 5000);
        }
      } catch (err) {
        console.error("Error checking access:", err);
      }
    };

    checkAccess();
  }, []);

  const loadRazorpayScript = () => {
    return new Promise((resolve) => {
      if ((window as any).Razorpay) {
        resolve(true);
        return;
      }

      const script = document.createElement("script");
      script.src = "https://checkout.razorpay.com/v1/checkout.js";
      script.async = true;
      script.onload = () => resolve(true);
      script.onerror = () => resolve(false);
      document.body.appendChild(script);
    });
  };

  const handlePayment = async () => {
    try {
      setProcessingSubscription(true);
      const userId = Number(localStorage.getItem("user_id"));
      const userEmail = "user@example.com"; // Replace with actual user email
      
      if (!userId) throw new Error("User ID not found");

      const razorpayLoaded = await loadRazorpayScript();
      if (!razorpayLoaded) throw new Error("Payment gateway failed to load");

      const response = await fetch("http://127.0.0.1:8000/api/subscription/create/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          user_id: userId,
          email: userEmail 
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Subscription failed");

      // Redirect to Razorpay payment page
      window.location.href = data.redirect_url;

    } catch (error) {
      setError(error.message);
      setProcessingSubscription(false);
    }
  };

  const handleCrawl = async () => {
    try {
      if (!userStatus.hasAccess) {
        setError(userStatus.message || "Please subscribe to continue");
        return;
      }

      setLoading(true);
      setError("");
      
      const userId = localStorage.getItem("user_id");
      if (!userId) throw new Error("User ID not found");

      let requestBody = {};
      if (keyword) {
        requestBody = { keyword, user_id: userId };
      } else if (url) {
        requestBody = { url, user_id: userId };
      } else {
        throw new Error("Please enter a keyword or URL");
      }

      const response = await fetch("http://127.0.0.1:8000/api/crawl/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Crawling failed");

      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getTrialMessage = () => {
    if (userStatus.isTrial && userStatus.trialEnds) {
      const daysLeft = Math.ceil(
        (new Date(userStatus.trialEnds).getTime() - new Date().getTime()) /
          (1000 * 60 * 60 * 24)
      );
      if (daysLeft > 0) return `Your trial ends in ${daysLeft} day(s)`;
      return "Your trial has expired";
    }
    return "";
  };

  const visibleLinks = userStatus.hasAccess
    ? results?.links || []
    : results?.links?.slice(0, 20) || [];

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-900 text-white p-6 relative">
      {showWelcome && (
        <div className="fixed top-4 left-4 bg-green-600 text-white px-6 py-3 rounded-lg shadow-xl z-50 animate-fade-in-out">
          🎉 Welcome to Premium!
        </div>
      )}

      {/* Instruction Icon */}
      <button 
        onClick={() => setShowInstructions(true)}
        className="fixed top-4 right-4 bg-gray-700 hover:bg-gray-600 text-white rounded-full w-8 h-8 flex items-center justify-center cursor-pointer z-40"
        aria-label="Instructions"
      >
        i
      </button>

      {/* Instructions Modal */}
      {showInstructions && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 text-white p-6 rounded-lg max-w-md w-full mx-4">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-bold">How to Use Odin Crawler</h3>
              <button 
                onClick={() => setShowInstructions(false)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-blue-400">Input Options:</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Enter a keyword in the first input field</li>
                  <li>OR enter a specific URL in the second field</li>
                  <li>(Both fields are optional but at least one is required)</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-blue-400">Initiate Crawl:</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Click the "Crawl" button</li>
                  <li>If not subscribed, the payment modal will appear</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold text-blue-400">View Results:</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>Title (if available)</li>
                  <li>Text content</li>
                  <li>Images (thumbnails)</li>
                  <li>Links (limited during trial)</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      <h1 className="text-3xl font-bold mb-6">🔍 Odin Crawler</h1>

      {/* Subscription Status */}
      {userStatus.status === 'active' && (
        <div className="bg-green-500 text-white p-3 rounded mb-4 w-full max-w-2xl">
          Premium Subscription Active
        </div>
      )}

      {/* Trial Message */}
      {userStatus.isTrial && userStatus.hasAccess && (
        <div className="bg-yellow-500 text-black p-3 rounded mb-4 w-full max-w-2xl">
          <div className="flex justify-between items-center">
            <span>{getTrialMessage()}</span>
            <button
              onClick={handlePayment}
              className="ml-4 bg-green-600 hover:bg-green-700 text-white text-sm font-bold py-1 px-3 rounded-full transition"
              disabled={processingSubscription}
            >
              {processingSubscription ? "Processing..." : "Subscribe Now"}
            </button>
          </div>
        </div>
      )}

      {/* Subscription Required */}
      {!userStatus.hasAccess && !userStatus.isTrial && (
        <div className="bg-red-500 text-white p-4 rounded-lg mb-6 w-full max-w-2xl text-center">
          <h3 className="text-xl font-bold mb-2">🔒 Premium Required</h3>
          <p className="mb-4">
            {userStatus.reason === 'trial_expired'
              ? "Your trial has expired. Subscribe to continue."
              : "Subscribe to unlock Odin Crawler"}
          </p>
          <button
            onClick={handlePayment}
            className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-6 rounded-full transition"
            disabled={processingSubscription}
          >
            {processingSubscription ? "Processing..." : "Subscribe Now"}
          </button>
        </div>
      )}

      <div className="flex flex-wrap justify-center gap-4 w-full max-w-2xl">
        <input
          type="text"
          placeholder="Enter keyword"
          className="flex-1 p-2 rounded bg-gray-700 text-white border border-gray-600 focus:outline-none focus:ring focus:ring-blue-500"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
        />
        <input
          type="text"
          placeholder="Enter URL"
          className="flex-1 p-2 rounded bg-gray-700 text-white border border-gray-600 focus:outline-none focus:ring focus:ring-blue-500"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button
          onClick={handleCrawl}
          className="p-2 bg-blue-500 rounded hover:bg-blue-600 transition disabled:bg-gray-500"
          disabled={loading || !userStatus.hasAccess}
        >
          {loading ? "Crawling..." : "Crawl"}
        </button>
      </div>

      {error && (
        <div className="mt-4 p-2 bg-red-500 text-white rounded">{error}</div>
      )}

      {results && (
        <div className="mt-8 w-full max-w-4xl bg-gray-800 p-6 rounded-lg">
          <h2 className="text-2xl font-bold mb-4">Results</h2>
          {results.title && <p><strong>Title:</strong> {results.title}</p>}
          {results.text_content && (
            <div>
              <strong>Text Content:</strong>
              <p className="whitespace-pre-wrap">{results.text_content}</p>
            </div>
          )}
          {results.images?.length > 0 && (
            <div>
              <strong>Images:</strong>
              <div className="flex flex-wrap gap-4 mt-2">
                {results.images.map((img, index) => (
                  <img
                    key={index}
                    src={img}
                    alt={`Image ${index + 1}`}
                    className="w-32 h-32 object-cover rounded-lg border border-gray-600"
                  />
                ))}
              </div>
            </div>
          )}
          {visibleLinks.length > 0 && (
            <div>
              <strong>Links:</strong>
              <ul>
                {visibleLinks.map((link, index) => (
                  <li key={index}>
                    <a
                      href={link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 underline hover:text-blue-600"
                    >
                      {link}
                    </a>
                  </li>
                ))}
              </ul>
              {userStatus.isTrial && results.links && results.links.length > 20 && (
                <div className="mt-2 text-yellow-400">
                  Showing first 20 links. Subscribe to unlock all.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {processingSubscription && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white text-black p-6 rounded-lg max-w-md">
            <h3 className="text-xl font-bold mb-4">Processing Payment</h3>
            <p>Redirecting to payment gateway...</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default OdinCrawler;