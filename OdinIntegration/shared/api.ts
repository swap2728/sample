import { EndpointConfig } from './types';

// Define available API endpoints
export const API_ENDPOINTS: EndpointConfig[] = [
  {
    id: 'users',
    name: 'User Service',
    path: '/api/users',
    method: 'GET'
  },
  {
    id: 'data',
    name: 'Data Service',
    path: '/api/data',
    method: 'GET'
  },
  {
    id: 'auth',
    name: 'Auth Service',
    path: '/api/auth',
    method: 'POST'
  }
];
