export interface ApiStatus {
  connected: boolean;
  latency?: string;
  version?: string;
  error?: string;
}

export interface EndpointStatus {
  success: boolean;
  status?: number;
  responseTime?: string;
  error?: string;
}

export interface EndpointConfig {
  id: string;
  name: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
}

export interface ApiResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: any;
  responseTime: string;
}

export interface ApiError {
  status: number;
  statusText: string;
  headers?: Record<string, string>;
  error: string;
  details?: string;
  responseTime?: string;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
