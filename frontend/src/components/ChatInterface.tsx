import { useState, useRef, useEffect } from 'react';
import { Bot, Send, Image, Mic, FileText, Shield, Globe, Info } from 'lucide-react';
import TextOptions from './TextOptions';
import ImageOptions from './ImageOptions';
import AudioOptions from './AudioOptions';
import ExploitOptions from './ExploitOptions';
import DarkWebOptions from './DarkWebOptions';
import { InstructionsPopup } from './InstructionsPopup';

type Message = {
  text: string;
  isUser: boolean;
  loading?: boolean;
  isSystem?: boolean;
};

export default function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([
    { text: 'Hello! How may I assist you today?', isUser: false }
  ]);
  const [input, setInput] = useState('');
  const [showTextOptions, setShowTextOptions] = useState(false);
  const [showImageOptions, setShowImageOptions] = useState(false);
  const [showAudioOptions, setShowAudioOptions] = useState(false);
  const [showExploitOptions, setShowExploitOptions] = useState(false);
  const [showDarkWebOptions, setShowDarkWebOptions] = useState(false);
  const [showHelpPopup, setShowHelpPopup] = useState(false);
  const [showSubscriptionPopup, setShowSubscriptionPopup] = useState(false);
  const [userStatus, setUserStatus] = useState({
    hasAccess: false,
    isTrial: true,
    trialEnds: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
    status: 'trial'
  });

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    const checkAccess = async () => {
      try {
        const userId = localStorage.getItem("user_id");
        if (!userId) {
          setUserStatus({
            hasAccess: false,
            isTrial: true,
            trialEnds: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
            status: 'trial'
          });
          return;
        }

        const response = await fetch(
          `http://localhost:8000/api/check-access/?user_id=${userId}`
        );
        const data = await response.json();
        
        if (response.ok) {
          setUserStatus({
            hasAccess: data.access,
            isTrial: data.is_trial,
            trialEnds: data.trial_ends || new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
            status: data.status,
          });
        }
      } catch (err) {
        console.error("Error checking access:", err);
        setUserStatus({
          hasAccess: false,
          isTrial: true,
          trialEnds: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
          status: 'trial'
        });
      }
    };

    checkAccess();
  }, []);

  const handleSend = () => {
    if (!input.trim()) return;

    setMessages((prev) => [
      ...prev,
      { text: input, isUser: true },
      { text: 'Processing your request...', isUser: false, loading: true }
    ]);
    setInput('');

    setTimeout(() => {
      setMessages((prev) =>
        prev
          .filter((msg) => !msg.loading)
          .concat({ text: 'I understand your request. How else may I assist you?', isUser: false })
      );
    }, 1500);
  };

  const handleTextOptionSelect = (option: string, response: string) => {
    setMessages((prev) => [
      ...prev,
      { text: option, isUser: true },
      { text: response, isUser: false }
    ]);
  };

  const handleSubscribe = () => {
    window.location.href = "https://rzp.io/rzp/NOdF9p5b";
    
    setTimeout(() => {
      setUserStatus({
        hasAccess: true,
        isTrial: false,
        trialEnds: '',
        status: 'premium'
      });
      setMessages(prev => [
        ...prev,
        { text: 'Your subscription was successful! You now have access to all premium features.', isUser: false, isSystem: true }
      ]);
    }, 3000);
  };

  const getTrialMessage = () => {
    if (userStatus.isTrial && userStatus.trialEnds) {
      const daysLeft = Math.ceil(
        (new Date(userStatus.trialEnds).getTime() - Date.now()) / 
        (1000 * 60 * 60 * 24)
      );
      
      if (daysLeft > 0) {
        return `⏳ Free Trial: ${daysLeft} day${daysLeft > 1 ? 's' : ''} remaining - Upgrade for full access`;
      } else {
        return "🔒 Your trial has ended. Subscribe to continue using premium features";
      }
    }
    return "";
  };

  const isTrialExpired = () => {
    if (userStatus.isTrial && userStatus.trialEnds) {
      return new Date(userStatus.trialEnds).getTime() < Date.now();
    }
    return false;
  };

  const handlePremiumFeatureClick = (featureName: string) => {
    if (!userStatus.hasAccess) {
      setShowSubscriptionPopup(true);
      setMessages(prev => [
        ...prev,
        { text: `🔒 Premium feature: ${featureName} requires subscription`, isUser: false, isSystem: true },
        { text: 'Upgrade now to unlock this capability', isUser: false, isSystem: true }
      ]);
      return true;
    }
    return false;
  };

  const executeExploit = () => {
    setMessages(prev => [
      ...prev,
      { text: 'Initializing zero-click exploit sequence...', isUser: false, loading: true }
    ]);
    
    setTimeout(() => {
      setMessages(prev => [
        ...prev.filter(msg => !msg.loading),
        { 
          text: '✅ Exploit executed successfully\n\nTarget system compromised\nData exfiltration complete', 
          isUser: false 
        }
      ]);
    }, 2000);
  };

  const executeDarkWebSearch = () => {
    setMessages(prev => [
      ...prev,
      { text: 'Querying dark web databases...', isUser: false, loading: true }
    ]);
    
    setTimeout(() => {
      setMessages(prev => [
        ...prev.filter(msg => !msg.loading),
        { 
          text: '✅ Dark web scan completed\n\nFound 23 relevant records containing sensitive data', 
          isUser: false 
        }
      ]);
    }, 2500);
  };

  return (
    <div className="flex flex-col h-screen bg-[#343541] relative">
      {/* Information Button Only */}
      <div className="absolute top-4 right-4">
        <button 
          onClick={() => setShowHelpPopup(true)}
          className="p-2 rounded-lg transition-colors hover:bg-gray-700 z-10"
          title="Instructions"
        >
          <Info className="w-6 h-6 text-white" />
        </button>
      </div>

      {/* Professional Trial Notification with Upgrade Button */}
      {(userStatus.isTrial || !userStatus.hasAccess) && (
        <div className={`p-3 text-center ${
          isTrialExpired() 
            ? 'bg-gradient-to-r from-red-500 to-red-600' 
            : 'bg-gradient-to-r from-yellow-500 to-yellow-600'
        } text-white font-medium shadow-md`}>
          <div className="max-w-6xl mx-auto flex items-center justify-center gap-2">
            <span>{getTrialMessage()}</span>
            {!isTrialExpired() && (
              <button 
                onClick={() => setShowSubscriptionPopup(true)}
                className="ml-2 px-3 py-1 bg-white text-yellow-700 rounded-md text-sm font-semibold hover:bg-gray-100 transition"
              >
                Subscribe
              </button>
            )}
          </div>
        </div>
      )}

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto p-6">
        {messages.map((message, index) => (
          <div key={index} className={`flex items-start gap-4 mb-6 ${message.loading ? 'animate-pulse' : ''} ${message.isSystem ? 'opacity-75' : ''}`}>
            {!message.isUser && !message.isSystem && <Bot className="w-8 h-8 text-white mt-1" />}
            {message.isSystem && <Info className="w-8 h-8 text-yellow-400 mt-1" />}
            <div className={`rounded-lg p-4 max-w-[80%] ${
              message.isUser ? 'bg-[#40414F] ml-auto' : 
              message.isSystem ? 'bg-yellow-900' : 'bg-[#444654]'
            }`}>
              <p className="text-white whitespace-pre-wrap">{message.text}</p>
            </div>
            {message.isUser && (
              <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
                <span className="text-white text-sm">You</span>
              </div>
            )}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="border-t border-gray-700 p-4">
        <div className="max-w-4xl mx-auto flex gap-4">
          <div className="flex-1 flex items-center gap-2 bg-[#40414F] rounded-lg p-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Type your message..."
              className="flex-1 bg-transparent text-white outline-none"
            />
            <div className="flex gap-2">
              <button
                onClick={() => setShowTextOptions(true)}
                className="p-2 rounded-lg transition-colors hover:bg-gray-700"
                title="Text Options"
              >
                <FileText className="w-5 h-5 text-white" />
              </button>
              <button
                onClick={() => setShowImageOptions(true)}
                className="p-2 rounded-lg transition-colors hover:bg-gray-700"
                title="Image Options"
              >
                <Image className="w-5 h-5 text-white" />
              </button>
              <button
                onClick={() => setShowAudioOptions(true)}
                className="p-2 rounded-lg transition-colors hover:bg-gray-700"
                title="Audio Options"
              >
                <Mic className="w-5 h-5 text-white" />
              </button>
              <button
                onClick={() => {
                  if (handlePremiumFeatureClick("Zero Click Exploit")) return;
                  setShowExploitOptions(true);
                }}
                className={`p-2 rounded-lg transition-colors ${userStatus.hasAccess ? 'hover:bg-gray-700' : 'opacity-50 cursor-not-allowed'}`}
                title={userStatus.hasAccess ? "Zero Click Exploit" : "Subscribe to access"}
              >
                <Shield className="w-5 h-5 text-white" />
              </button>
              <button
                onClick={() => {
                  if (handlePremiumFeatureClick("Dark Web Extraction")) return;
                  setShowDarkWebOptions(true);
                }}
                className={`p-2 rounded-lg transition-colors ${userStatus.hasAccess ? 'hover:bg-gray-700' : 'opacity-50 cursor-not-allowed'}`}
                title={userStatus.hasAccess ? "Dark Web Extraction" : "Subscribe to access"}
              >
                <Globe className="w-5 h-5 text-white" />
              </button>
            </div>
            <button 
              onClick={handleSend} 
              className="p-2 rounded-lg transition-colors hover:bg-gray-700"
            >
              <Send className="w-5 h-5 text-white" />
            </button>
          </div>
        </div>
      </div>

      {/* Instruction Popup */}
      {showHelpPopup && (
        <InstructionsPopup onClose={() => setShowHelpPopup(false)} />
      )}

      {/* Subscription Popup */}
      {showSubscriptionPopup && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-[#40414F] rounded-lg p-6 max-w-md w-full border border-gray-600 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-4">
              {userStatus.isTrial ? 'Upgrade to Premium' : 'Get Started'}
            </h2>
            <p className="text-gray-300 mb-4">
              {userStatus.isTrial 
                ? 'Your trial period will end soon. Upgrade now to keep access to:'
                : 'Start with a 3-day free trial to access:'}
            </p>
            <ul className="text-gray-300 mb-6 list-disc pl-5 space-y-2">
              <li>Zero Click Exploit</li>
              <li>Dark Web Extraction</li>
            </ul>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowSubscriptionPopup(false)}
                className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition"
              >
                {userStatus.isTrial ? 'Later' : 'Cancel'}
              </button>
              <button
                onClick={handleSubscribe}
                className="px-4 py-2 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition shadow-md"
              >
                {userStatus.isTrial ? 'Subscribe Now' : 'Start Free Trial'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Option Modals */}
      {showTextOptions && (
        <TextOptions
          onClose={() => setShowTextOptions(false)}
          onSelectOption={handleTextOptionSelect}
        />
      )}
      {showImageOptions && <ImageOptions onClose={() => setShowImageOptions(false)} />}
      {showAudioOptions && <AudioOptions onClose={() => setShowAudioOptions(false)} />}
      
      {showExploitOptions && userStatus.hasAccess && (
        <ExploitOptions 
          onClose={() => setShowExploitOptions(false)}
          onExecute={executeExploit}
        />
      )}
      
      {showDarkWebOptions && userStatus.hasAccess && (
        <DarkWebOptions 
          onClose={() => setShowDarkWebOptions(false)}
          onExecute={executeDarkWebSearch}
        />
      )}
    </div>
  );
}