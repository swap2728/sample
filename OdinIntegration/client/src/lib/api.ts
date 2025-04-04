import { apiRequest } from './queryClient';
import type { ApiStatus, EndpointStatus, ApiResponse, ApiError, HttpMethod } from '@shared/types';
import { API_ENDPOINTS } from '@shared/api';

// Check API connection status
export async function checkApiStatus(): Promise<ApiStatus> {
  try {
    const startTime = performance.now();
    const response = await fetch('/api/status', {
      method: 'GET',
      credentials: 'include'
    });

    const endTime = performance.now();
    const latency = `${Math.round(endTime - startTime)}ms`;

    if (!response.ok) {
      throw new Error(`API responded with status ${response.status}`);
    }

    const data = await response.json();
    return {
      connected: true,
      latency,
      version: data.version
    };
  } catch (error) {
    console.error('API Status check failed:', error);
    return {
      connected: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

// Check authentication status
export async function checkAuthStatus(): Promise<{authenticated: boolean; expiresAt?: string; error?: string}> {
  try {
    const response = await fetch('/api/auth/check', {
      method: 'GET',
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error(`Auth check failed with status ${response.status}`);
    }

    const data = await response.json();
    return {
      authenticated: data.authenticated,
      expiresAt: data.expiresAt
    };
  } catch (error) {
    console.error('Auth status check failed:', error);
    return {
      authenticated: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

// Test a specific endpoint
export async function testEndpoint(endpointId: string): Promise<EndpointStatus> {
  try {
    const endpoint = API_ENDPOINTS.find(ep => ep.id === endpointId);
    if (!endpoint) {
      throw new Error(`Unknown endpoint: ${endpointId}`);
    }

    const startTime = performance.now();
    const response = await fetch(endpoint.path, {
      method: endpoint.method,
      credentials: 'include',
      headers: endpoint.method !== 'GET' ? { 'Content-Type': 'application/json' } : undefined,
      body: endpoint.method !== 'GET' ? JSON.stringify({}) : undefined
    });

    const endTime = performance.now();
    const responseTime = `${Math.round(endTime - startTime)}ms`;

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(errorData || `API responded with status ${response.status}`);
    }

    return {
      success: true,
      status: response.status,
      responseTime
    };
  } catch (error) {
    console.error(`Test endpoint ${endpointId} failed:`, error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

// Send a custom API request
export async function sendCustomRequest(
  method: HttpMethod,
  endpoint: string,
  headers: Record<string, string>,
  body?: any
): Promise<ApiResponse | ApiError> {
  try {
    const fullEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const apiEndpoint = fullEndpoint.startsWith('/api/') ? fullEndpoint : `/api/${fullEndpoint}`;
    
    const startTime = performance.now();
    const response = await fetch(apiEndpoint, {
      method,
      headers: {
        ...headers,
        'Content-Type': 'application/json'
      },
      body: ['POST', 'PUT', 'PATCH'].includes(method) && body ? JSON.stringify(body) : undefined,
      credentials: 'include'
    });

    const endTime = performance.now();
    const responseTime = `${Math.round(endTime - startTime)}ms`;

    // Extract headers
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    if (!response.ok) {
      const errorText = await response.text();
      let errorJson;
      
      try {
        errorJson = JSON.parse(errorText);
      } catch (e) {
        // If it's not JSON, use the text as is
      }
      
      return {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        error: errorJson?.error || errorJson?.message || errorText || 'Request failed',
        details: errorJson?.details || errorJson?.error_description || '',
        responseTime
      };
    }

    const data = await response.json().catch(() => ({}));
    
    return {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
      data,
      responseTime
    };
  } catch (error) {
    console.error('Custom request failed:', error);
    return {
      status: 0,
      statusText: 'Network Error',
      error: error instanceof Error ? error.message : 'Unknown network error',
      details: 'Could not complete the request. Check your network connection.'
    };
  }
}
