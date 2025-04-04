import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { API_ENDPOINTS } from "@shared/api";

export async function registerRoutes(app: Express): Promise<Server> {
  // API Status endpoint
  app.get('/api/status', (req: Request, res: Response) => {
    res.json({
      connected: true,
      latency: `${Math.floor(Math.random() * 20) + 30}ms`,
      version: '1.0.0'
    });
  });

  // Authentication check endpoint
  app.get('/api/auth/check', (req: Request, res: Response) => {
    res.json({
      authenticated: true,
      expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString() // 30 minutes from now
    });
  });

  // User Service endpoint
  app.get('/api/users', async (req: Request, res: Response) => {
    try {
      // Simulate some processing time
      await new Promise(resolve => setTimeout(resolve, 50));
      
      res.json({
        success: true,
        data: []
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to fetch users'
      });
    }
  });

  // Data Service endpoint
  app.get('/api/data', async (req: Request, res: Response) => {
    try {
      // Simulate some processing time
      await new Promise(resolve => setTimeout(resolve, 70));
      
      res.json({
        success: true,
        data: {}
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to fetch data'
      });
    }
  });

  // Auth Service endpoint
  app.post('/api/auth', async (req: Request, res: Response) => {
    try {
      // Simulate some processing time
      await new Promise(resolve => setTimeout(resolve, 90));
      
      res.json({
        success: true,
        token: 'sample-token',
        expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString() // 30 minutes from now
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Authentication failed'
      });
    }
  });

  // Generic API endpoint to handle any request for testing
  app.all('/api/:path(*)', (req: Request, res: Response) => {
    const startTime = Date.now();
    const path = req.params.path;
    const method = req.method;
    
    // Random response time between 50ms and
    const responseTime = Math.floor(Math.random() * 150) + 50;
    
    setTimeout(() => {
      // Randomly succeed (80%) or fail (20%)
      if (Math.random() > 0.2) {
        res.status(200).json({
          success: true,
          message: 'Operation completed successfully',
          data: {
            id: 123,
            timestamp: new Date().toISOString(),
            method: method,
            path: `/api/${path}`,
            body: req.body,
            query: req.query
          }
        });
      } else {
        res.status(500).json({
          success: false,
          error: 'Failed to process the request',
          details: 'Backend server encountered an error'
        });
      }
    }, responseTime);
  });

  const httpServer = createServer(app);

  return httpServer;
}
