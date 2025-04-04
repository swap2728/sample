import { useState, useEffect } from 'react';
import { checkApiStatus, checkAuthStatus } from '@/lib/api';

interface ConnectionStatusProps {
  onStatusUpdate: (connected: boolean) => void;
}

export function ConnectionPanel({ onStatusUpdate }: ConnectionStatusProps) {
  const [apiConnection, setApiConnection] = useState<{
    status: 'checking' | 'connected' | 'failed';
    latency?: string;
    lastCheck?: string;
    endpoint?: string;
  }>({
    status: 'checking',
    endpoint: '/api/status'
  });

  const [authStatus, setAuthStatus] = useState<{
    status: 'checking' | 'authenticated' | 'unauthenticated';
    method?: string;
    expiresAt?: string;
  }>({
    status: 'checking',
    method: 'Bearer Token'
  });

  useEffect(() => {
    checkConnection();
  }, []);

  const checkConnection = async () => {
    // Update connection status to checking
    setApiConnection(prev => ({ ...prev, status: 'checking' }));
    setAuthStatus(prev => ({ ...prev, status: 'checking' }));

    try {
      // Check API status
      const apiStatus = await checkApiStatus();
      
      setApiConnection({
        status: apiStatus.connected ? 'connected' : 'failed',
        latency: apiStatus.latency,
        lastCheck: new Date().toLocaleTimeString(),
        endpoint: '/api/status'
      });

      // Only check auth if API is connected
      if (apiStatus.connected) {
        const auth = await checkAuthStatus();
        
        setAuthStatus({
          status: auth.authenticated ? 'authenticated' : 'unauthenticated',
          method: 'Bearer Token',
          expiresAt: auth.expiresAt ? new Date(auth.expiresAt).toLocaleTimeString() : undefined
        });
      } else {
        setAuthStatus({
          status: 'unauthenticated',
          method: 'Bearer Token'
        });
      }

      // Notify parent component about the status
      onStatusUpdate(apiStatus.connected);
    } catch (error) {
      console.error("Error checking connection:", error);
      
      setApiConnection({
        status: 'failed',
        lastCheck: new Date().toLocaleTimeString(),
        endpoint: '/api/status'
      });
      
      setAuthStatus({
        status: 'unauthenticated',
        method: 'Bearer Token'
      });

      // Notify parent component about the status
      onStatusUpdate(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow mb-6 overflow-hidden">
      <div className="px-4 py-5 sm:px-6 bg-gray-50 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-900">Backend Connection Status</h2>
        <p className="mt-1 text-sm text-gray-500">View and monitor connection between frontend and backend systems</p>
      </div>
      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* API Connection Status Card */}
          <div className="border rounded-lg p-4 bg-gray-50">
            <h3 className="text-md font-medium text-gray-700 mb-2">API Connection</h3>
            <div className="flex items-center mb-4">
              <div 
                className={`w-3 h-3 rounded-full mr-2 ${
                  apiConnection.status === 'checking' ? 'bg-yellow-400' : 
                  apiConnection.status === 'connected' ? 'bg-green-500' : 'bg-red-500'
                }`}
              />
              <span className="text-sm text-gray-600">
                {apiConnection.status === 'checking' ? 'Initializing connection...' : 
                 apiConnection.status === 'connected' ? `Connected (Latency: ${apiConnection.latency || 'N/A'})` : 
                 'Connection failed'}
              </span>
            </div>
            <div className="text-xs text-gray-500">
              <div className="mb-1">Endpoint: <span className="font-mono">{apiConnection.endpoint}</span></div>
              <div>Last Check: <span>{apiConnection.lastCheck || '--'}</span></div>
            </div>
          </div>
          
          {/* Authentication Status Card */}
          <div className="border rounded-lg p-4 bg-gray-50">
            <h3 className="text-md font-medium text-gray-700 mb-2">Authentication Status</h3>
            <div className="flex items-center mb-4">
              <div 
                className={`w-3 h-3 rounded-full mr-2 ${
                  authStatus.status === 'checking' ? 'bg-yellow-400' : 
                  authStatus.status === 'authenticated' ? 'bg-green-500' : 'bg-red-500'
                }`}
              />
              <span className="text-sm text-gray-600">
                {authStatus.status === 'checking' ? 'Checking authentication...' : 
                 authStatus.status === 'authenticated' ? 'Authenticated' : 'Not authenticated'}
              </span>
            </div>
            <div className="text-xs text-gray-500">
              <div>Auth Method: <span>{authStatus.method}</span></div>
              <div>Session Expires: <span>{authStatus.expiresAt || '--'}</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
