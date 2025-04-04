import { useState } from 'react';
import { sendCustomRequest } from '@/lib/api';
import type { HttpMethod, ApiResponse, ApiError } from '@shared/types';

interface RequestResponsePanelProps {
  showToast: (message: string, type: 'error' | 'success') => void;
}

export function RequestResponsePanel({ showToast }: RequestResponsePanelProps) {
  const [method, setMethod] = useState<HttpMethod>('GET');
  const [endpoint, setEndpoint] = useState('');
  const [headers, setHeaders] = useState('{\n  "Content-Type": "application/json"\n}');
  const [body, setBody] = useState('{\n  "key": "value"\n}');
  const [loading, setLoading] = useState(false);
  
  const [response, setResponse] = useState<{
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
    body?: any;
    error?: string;
    responseTime?: string;
  }>({});

  const handleSendRequest = async () => {
    // Validate JSON inputs
    let parsedHeaders = {};
    let parsedBody = {};
    
    try {
      if (headers.trim()) {
        parsedHeaders = JSON.parse(headers);
      }
    } catch (e) {
      showToast('Invalid JSON in headers', 'error');
      return;
    }
    
    try {
      if (body.trim() && ['POST', 'PUT', 'PATCH'].includes(method)) {
        parsedBody = JSON.parse(body);
      }
    } catch (e) {
      showToast('Invalid JSON in request body', 'error');
      return;
    }
    
    // Update UI for loading state
    setLoading(true);
    setResponse({
      status: undefined,
      statusText: 'Loading...',
      headers: undefined,
      body: undefined,
      error: undefined,
      responseTime: undefined
    });
    
    try {
      const result = await sendCustomRequest(method, endpoint, parsedHeaders, parsedBody);
      
      if ('error' in result) {
        // This is an error response
        setResponse({
          status: result.status,
          statusText: result.statusText,
          headers: result.headers,
          error: result.error,
          body: undefined,
          responseTime: result.responseTime
        });
      } else {
        // This is a success response
        setResponse({
          status: result.status,
          statusText: result.statusText,
          headers: result.headers,
          body: result.data,
          error: undefined,
          responseTime: result.responseTime
        });
      }
    } catch (error) {
      setResponse({
        status: 0,
        statusText: 'Request Failed',
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      });
      
      showToast('Request failed: ' + (error instanceof Error ? error.message : 'Unknown error'), 'error');
    } finally {
      setLoading(false);
    }
  };

  const getStatusClassName = () => {
    if (!response.status) return 'bg-gray-400';
    if (response.status >= 200 && response.status < 300) return 'bg-green-500';
    if (response.status >= 400) return 'bg-red-500';
    return 'bg-yellow-500';
  };

  return (
    <div className="bg-white rounded-lg shadow">
      <div className="px-4 py-5 sm:px-6 bg-gray-50 border-b border-gray-200">
        <h2 className="text-lg font-medium text-gray-900">API Request & Response</h2>
        <p className="mt-1 text-sm text-gray-500">Test API requests and view responses</p>
      </div>
      <div className="p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Request Panel */}
          <div>
            <h3 className="text-md font-medium text-gray-700 mb-3">Request</h3>
            <div className="mb-4">
              <label htmlFor="request-method" className="block text-sm font-medium text-gray-700 mb-1">Method</label>
              <select 
                id="request-method" 
                value={method}
                onChange={(e) => setMethod(e.target.value as HttpMethod)}
                disabled={loading}
                className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary focus:border-primary block w-full p-2.5"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
              </select>
            </div>
            
            <div className="mb-4">
              <label htmlFor="request-endpoint" className="block text-sm font-medium text-gray-700 mb-1">Endpoint</label>
              <div className="flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-900 bg-gray-200 rounded-l-md border border-r-0 border-gray-300">
                  /api/
                </span>
                <input 
                  type="text" 
                  id="request-endpoint" 
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  disabled={loading}
                  className="rounded-none rounded-r-lg bg-gray-50 border border-gray-300 text-gray-900 focus:ring-primary focus:border-primary block flex-1 min-w-0 w-full text-sm p-2.5"
                  placeholder="endpoint"
                />
              </div>
            </div>
            
            <div className="mb-4">
              <label htmlFor="request-headers" className="block text-sm font-medium text-gray-700 mb-1">Headers (JSON)</label>
              <textarea 
                id="request-headers" 
                rows={3} 
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                disabled={loading}
                className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary focus:border-primary block w-full p-2.5 font-mono"
                placeholder='{"Content-Type": "application/json"}'
              />
            </div>
            
            <div className="mb-4">
              <label htmlFor="request-body" className="block text-sm font-medium text-gray-700 mb-1">Request Body (JSON)</label>
              <textarea 
                id="request-body" 
                rows={5} 
                value={body}
                onChange={(e) => setBody(e.target.value)}
                disabled={loading || !['POST', 'PUT', 'PATCH'].includes(method)}
                className={`bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-primary focus:border-primary block w-full p-2.5 font-mono ${
                  !['POST', 'PUT', 'PATCH'].includes(method) ? 'opacity-50' : ''
                }`}
                placeholder='{"key": "value"}'
              />
            </div>
            
            <button 
              onClick={handleSendRequest}
              disabled={loading || !endpoint.trim()}
              className={`w-full inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white ${
                loading || !endpoint.trim() 
                  ? 'bg-gray-400 cursor-not-allowed' 
                  : 'bg-primary hover:bg-indigo-700 focus:outline-none'
              }`}
            >
              {loading ? 'Sending...' : 'Send Request'}
            </button>
          </div>
          
          {/* Response Panel */}
          <div>
            <h3 className="text-md font-medium text-gray-700 mb-3">Response</h3>
            <div className="rounded-lg border border-gray-300 overflow-hidden mb-3">
              <div className="flex justify-between items-center bg-gray-50 px-4 py-2 border-b border-gray-300">
                <div className="flex items-center space-x-2">
                  <span className="text-sm font-medium text-gray-700">Status:</span>
                  <span id="response-status" className={`text-sm px-2 py-0.5 rounded-full text-white ${getStatusClassName()}`}>
                    {response.status ? `${response.status} ${response.statusText}` : '--'}
                  </span>
                </div>
                <div className="text-xs text-gray-500" id="response-time">
                  Time: {response.responseTime || '--'}
                </div>
              </div>
              <div className="p-4">
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-1">Response Headers</label>
                  <pre className="bg-gray-50 border border-gray-200 rounded-lg p-3 text-xs font-mono text-gray-700 h-24 overflow-auto">
                    {response.headers ? JSON.stringify(response.headers, null, 2) : 'No response headers'}
                  </pre>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Response Body</label>
                  <pre className="bg-gray-50 border border-gray-200 rounded-lg p-3 text-xs font-mono text-gray-700 h-64 overflow-auto">
                    {response.body ? JSON.stringify(response.body, null, 2) : 'No response data'}
                  </pre>
                </div>
              </div>
            </div>
            {response.error && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
                {response.error}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
