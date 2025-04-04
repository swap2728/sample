import { useEffect, useState } from 'react';

interface ErrorToastProps {
  message: string;
  type: 'error' | 'success';
  onClose: () => void;
}

export function ErrorToast({ message, type, onClose }: ErrorToastProps) {
  const [visible, setVisible] = useState(true);
  
  useEffect(() => {
    // Auto-close after 5 seconds
    const timer = setTimeout(() => {
      setVisible(false);
      setTimeout(onClose, 300); // Allow for fade-out animation
    }, 5000);
    
    return () => clearTimeout(timer);
  }, [onClose]);
  
  const handleClose = () => {
    setVisible(false);
    setTimeout(onClose, 300); // Allow for fade-out animation
  };
  
  const bgColor = type === 'error' ? 'bg-red-100 border-red-500 text-red-700' : 'bg-green-100 border-green-500 text-green-700';
  const iconColor = type === 'error' ? 'text-red-500' : 'text-green-500';
  const hoverColor = type === 'error' ? 'hover:bg-red-200' : 'hover:bg-green-200';
  
  return (
    <div 
      className={`fixed bottom-4 right-4 ${bgColor} border-l-4 p-4 rounded shadow-md max-w-md transition-opacity duration-300 ${
        visible ? 'opacity-100' : 'opacity-0'
      }`}
    >
      <div className="flex">
        <div className="flex-shrink-0">
          {type === 'error' ? (
            <svg className={`h-5 w-5 ${iconColor}`} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
          ) : (
            <svg className={`h-5 w-5 ${iconColor}`} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          )}
        </div>
        <div className="ml-3">
          <p className="text-sm">{message}</p>
        </div>
        <div className="ml-auto pl-3">
          <div className="-mx-1.5 -my-1.5">
            <button 
              onClick={handleClose} 
              className={`inline-flex ${bgColor} ${hoverColor} rounded-md p-1.5 focus:outline-none`}
            >
              <svg className="h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
