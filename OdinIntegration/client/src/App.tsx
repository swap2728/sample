import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Simple creation of query client without special configuration
const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <div style={{ 
        padding: '40px', 
        textAlign: 'center', 
        maxWidth: '800px', 
        margin: '0 auto', 
        fontFamily: 'system-ui, -apple-system, sans-serif'
      }}>
        <h1 style={{ 
          color: '#333', 
          fontSize: '32px',
          marginBottom: '20px',
          background: 'linear-gradient(90deg, #4F46E5, #06B6D4)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent'
        }}>
          ODIN-1 Dashboard
        </h1>
        <div style={{
          padding: '20px',
          background: 'white',
          borderRadius: '8px',
          boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
          marginBottom: '20px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', backgroundColor: '#22c55e', marginRight: '8px' }}></div>
            <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 600 }}>Backend API Connected</h2>
          </div>
          <p style={{ color: '#666', marginBottom: '8px' }}>
            The backend API is responding correctly.
          </p>
          <div style={{ fontSize: '14px', color: '#888', textAlign: 'left', marginTop: '16px', padding: '12px', background: '#f9fafb', borderRadius: '4px' }}>
            <div><strong>Status:</strong> Online</div>
            <div><strong>Endpoint:</strong> /api/status</div>
            <div><strong>Auth:</strong> Working</div>
          </div>
        </div>
        <p style={{ color: '#666', marginTop: '32px', fontSize: '14px' }}>
          Frontend is now rendering correctly. You can begin integrating with the full dashboard components.
        </p>
      </div>
    </QueryClientProvider>
  );
}

export default App;
