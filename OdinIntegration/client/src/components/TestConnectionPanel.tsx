import { useState } from 'react';
import { testEndpoint } from '@/lib/api';
import { API_ENDPOINTS } from '@shared/api';
import type { EndpointConfig } from '@shared/types';

interface TestConnectionPanelProps {
  showToast: (message: string, type: 'error' | 'success') => void;
}

export function TestConnectionPanel({ showToast }: TestConnectionPanelProps) {
  const [endpoints, setEndpoints] = useState<(EndpointConfig & {
    status: 'not_tested' | 'testing' | 'success' | 'error';
    responseTime?: string;
    errorMessage?: string;
  })[]>(API_ENDPOINTS.map(endpoint => ({
    ...endpoint,
    status: 'not_tested'
  })));

  const handleTestEndpoint = async (endpointId: string) => {
    // Find the endpoint index
    const index = endpoints.findIndex(ep => ep.id === endpointId);
    if (index === -1) return;

    // Update status to testing
    setEndpoints(prev => prev.map((ep, i) => 
      i === index ? { ...ep, status: 'testing' } : ep
    ));

    try {
      const result = await testEndpoint(endpointId);
      
      if (result.success) {
        setEndpoints(prev => prev.map((ep, i) => 
          i === index ? { 
            ...ep, 
            status: 'success',
            responseTime: result.responseTime,
            errorMessage: undefined
          } : ep
        ));
      } else {
        setEndpoints(prev => prev.map((ep, i) => 
          i === index ? { 
            ...ep, 
            status: 'error',
            responseTime: undefined,
            errorMessage: result.error 
          } : ep
        ));
      }
    } catch (error) {
      setEndpoints(prev => prev.map((ep, i) => 
        i === index ? { 
          ...ep, 
          status: 'error',
          responseTime: undefined,
          errorMessage: error instanceof Error ? error.message : 'Unknown error'
        } : ep
      ));
      
      showToast(`Failed to test endpoint ${endpointId}: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
    }
  };

  const handleRunAllTests = async () => {
    // First set all endpoints to testing
    setEndpoints(prev => prev.map(ep => ({ ...ep, status: 'testing' })));

    // Test each endpoint in sequence
    for (const endpoint of endpoints) {
      try {
        const result = await testEndpoint(endpoint.id);
        
        setEndpoints(prev => prev.map(ep => 
          ep.id === endpoint.id ? { 
            ...ep, 
            status: result.success ? 'success' : 'error',
            responseTime: result.responseTime,
            errorMessage: result.success ? undefined : result.error
          } : ep
        ));
      } catch (error) {
        setEndpoints(prev => prev.map(ep => 
          ep.id === endpoint.id ? { 
            ...ep, 
            status: 'error',
            responseTime: undefined,
            errorMessage: error instanceof Error ? error.message : 'Unknown error'
          } : ep
        ));
      }
    }
  };

  const handleClearResults = () => {
    setEndpoints(prev => prev.map(ep => ({
      ...ep,
      status: 'not_tested',
      responseTime: undefined,
      errorMessage: undefined
    })));
  };

  return (
    <div className="bg-white rounded-lg shadow mb-6">
      <div className="px-4 py-5 sm:px-6 flex justify-between items-center bg-gray-50 border-b border-gray-200">
        <div>
          <h2 className="text-lg font-medium text-gray-900">Test API Endpoints</h2>
          <p className="mt-1 text-sm text-gray-500">Verify connectivity to specific backend services</p>
        </div>
        <div className="flex space-x-2">
          <button 
            onClick={handleRunAllTests}
            className="inline-flex items-center px-3 py-1.5 text-xs font-medium rounded bg-primary text-white hover:bg-indigo-700 focus:outline-none"
          >
            Run All Tests
          </button>
          <button 
            onClick={handleClearResults}
            className="inline-flex items-center px-3 py-1.5 text-xs font-medium rounded bg-gray-200 text-gray-700 hover:bg-gray-300 focus:outline-none"
          >
            Clear Results
          </button>
        </div>
      </div>

      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {endpoints.map(endpoint => (
            <div key={endpoint.id} className="border rounded-lg overflow-hidden" data-endpoint-id={endpoint.id}>
              <div className="px-4 py-3 bg-gray-50 border-b">
                <h3 className="font-medium text-sm text-gray-700">{endpoint.name}</h3>
                <p className="text-xs text-gray-500 mt-1">{endpoint.path}</p>
              </div>
              <div className="p-4">
                <div className="flex justify-between items-center mb-3">
                  <span className="text-xs text-gray-500">{endpoint.method}</span>
                  <div className="endpoint-status flex items-center">
                    <div 
                      className={`w-2 h-2 rounded-full mr-1 ${
                        endpoint.status === 'not_tested' ? 'bg-gray-300' :
                        endpoint.status === 'testing' ? 'bg-yellow-400' :
                        endpoint.status === 'success' ? 'bg-green-500' : 'bg-red-500'
                      }`}
                    />
                    <span className="text-xs text-gray-500">
                      {endpoint.status === 'not_tested' ? 'Not tested' :
                       endpoint.status === 'testing' ? 'Testing...' :
                       endpoint.status === 'success' ? 'Success' : 'Failed'}
                    </span>
                  </div>
                </div>
                <button 
                  onClick={() => handleTestEndpoint(endpoint.id)}
                  disabled={endpoint.status === 'testing'}
                  className={`w-full px-3 py-1.5 text-xs font-medium rounded ${
                    endpoint.status === 'testing' ? 'bg-gray-300 text-gray-500 cursor-not-allowed' :
                    'bg-gray-100 text-gray-700 hover:bg-gray-200 focus:outline-none'
                  }`}
                >
                  Test Connection
                </button>
                <div className="mt-3 text-xs">
                  {endpoint.responseTime && (
                    <div className="response-time">
                      Response Time: <span className="font-mono">{endpoint.responseTime}</span>
                    </div>
                  )}
                  {endpoint.errorMessage && (
                    <div className="error-message text-error">
                      {endpoint.errorMessage}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
