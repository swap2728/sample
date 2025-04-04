import { useState, useEffect } from 'react';
import { ConnectionPanel } from '@/components/ConnectionPanel';
import { TestConnectionPanel } from '@/components/TestConnectionPanel';
import { RequestResponsePanel } from '@/components/RequestResponsePanel';
import { ErrorToast } from '@/components/ErrorToast';

export default function Dashboard() {
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [toast, setToast] = useState<{
    visible: boolean;
    message: string;
    type: 'error' | 'success';
  }>({
    visible: false,
    message: '',
    type: 'error'
  });
  const [debugMode, setDebugMode] = useState(false);

  const handleApiStatusUpdate = (connected: boolean) => {
    setApiStatus(connected ? 'online' : 'offline');
  };

  const showToast = (message: string, type: 'error' | 'success') => {
    setToast({
      visible: true,
      message,
      type
    });
  };

  const closeToast = () => {
    setToast(prev => ({ ...prev, visible: false }));
  };

  const handleRefreshConnection = () => {
    setApiStatus('checking');
    // The ConnectionPanel will handle the actual refresh and update via onStatusUpdate
  };

  const toggleDebugMode = () => {
    setDebugMode(!debugMode);
    showToast(`Debug mode ${!debugMode ? 'enabled' : 'disabled'}`, 'success');
  };

  const clearCache = () => {
    if (confirm('This will clear all cached data and reset the application state. Continue?')) {
      // In a real app, we would clear localStorage, sessionStorage, etc.
      localStorage.clear();
      showToast('Cache cleared successfully', 'success');
    }
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <h1 className="text-xl font-semibold text-gray-800">ODIN-1 Dashboard</h1>
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <span className="text-sm text-gray-600 mr-2">API Status:</span>
              <span 
                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  apiStatus === 'checking' ? 'bg-yellow-100 text-yellow-800' :
                  apiStatus === 'online' ? 'bg-green-100 text-green-800' :
                  'bg-red-100 text-red-800'
                }`}
              >
                {apiStatus === 'checking' ? 'Checking...' :
                 apiStatus === 'online' ? 'Online' : 'Offline'}
              </span>
            </div>
            <button 
              onClick={handleRefreshConnection}
              className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded shadow-sm text-white bg-primary hover:bg-indigo-700 focus:outline-none"
            >
              Refresh Connection
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-grow max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <ConnectionPanel onStatusUpdate={handleApiStatusUpdate} />
        <TestConnectionPanel showToast={showToast} />
        <RequestResponsePanel showToast={showToast} />
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 py-4">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div className="text-sm text-gray-500">ODIN-1 Frontend-Backend Integration</div>
            <div className="flex space-x-4">
              <button 
                onClick={toggleDebugMode}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Debug Mode: {debugMode ? 'On' : 'Off'}
              </button>
              <button 
                onClick={clearCache}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Clear Cache
              </button>
            </div>
          </div>
        </div>
      </footer>

      {/* Error Toast */}
      {toast.visible && (
        <ErrorToast 
          message={toast.message}
          type={toast.type}
          onClose={closeToast}
        />
      )}
    </div>
  );
}
