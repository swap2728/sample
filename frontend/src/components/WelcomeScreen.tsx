import { useCallback } from 'react';
import { Bot, ArrowRight } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';

export default function WelcomeScreen({ onStart }: { onStart: () => void }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mouseRef = useRef({ x: 0, y: 0 });
  const [isButtonHovered, setIsButtonHovered] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let particles: Particle[] = [];

    const resizeCanvas = () => {
      const pixelRatio = window.devicePixelRatio || 1;
      canvas.width = window.innerWidth * pixelRatio;
      canvas.height = window.innerHeight * pixelRatio;
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
      ctx.scale(pixelRatio, pixelRatio);
    };
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    class Particle {
      x: number;
      y: number;
      size: number;
      speedX: number;
      speedY: number;
      color: string;
      alpha: number;
      targetAlpha: number;

      constructor() {
        this.x = Math.random() * window.innerWidth;
        this.y = Math.random() * window.innerHeight;
        this.size = Math.random() * 2 + 1;
        this.speedX = Math.random() * 0.2 - 0.1;
        this.speedY = Math.random() * 0.2 - 0.1;
        this.color = `hsl(${220 + Math.random() * 40}, 70%, 60%)`;
        this.alpha = Math.random() * 0.5 + 0.2;
        this.targetAlpha = this.alpha;
      }

      update() {
        const dx = mouseRef.current.x - this.x;
        const dy = mouseRef.current.y - this.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const maxDistance = 200;

        if (distance < maxDistance) {
          const force = (maxDistance - distance) / maxDistance;
          const angle = Math.atan2(dy, dx);
          const pushX = Math.cos(angle) * force * 2;
          const pushY = Math.sin(angle) * force * 2;
          
          this.speedX -= pushX * 0.1;
          this.speedY -= pushY * 0.1;
          this.targetAlpha = 0.8;
        } else {
          this.targetAlpha = this.alpha;
        }

        // Apply inertia and friction
        this.speedX *= 0.98;
        this.speedY *= 0.98;
        
        // Update position
        this.x += this.speedX;
        this.y += this.speedY;

        // Smooth alpha transition
        const alphaDiff = this.targetAlpha - this.alpha;
        this.alpha += alphaDiff * 0.1;

        // Wrap around edges
        if (this.x < 0) this.x = window.innerWidth;
        if (this.x > window.innerWidth) this.x = 0;
        if (this.y < 0) this.y = window.innerHeight;
        if (this.y > window.innerHeight) this.y = 0;
      }

      draw() {
        if (!ctx) return;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = this.color.replace(')', `,${this.alpha})`);
        ctx.fill();
      }
    }

    const init = () => {
      particles = [];
      const numberOfParticles = Math.min((window.innerWidth * window.innerHeight) / 8000, 300);
      for (let i = 0; i < numberOfParticles; i++) {
        particles.push(new Particle());
      }
    };

    const drawGradientBackground = () => {
      const gradient = ctx.createRadialGradient(
        window.innerWidth / 2,
        window.innerHeight / 2,
        0,
        window.innerWidth / 2,
        window.innerHeight / 2,
        window.innerWidth / 2
      );
      gradient.addColorStop(0, '#1a1b26');
      gradient.addColorStop(1, '#2a2b3d');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);
    };

    const animate = () => {
      drawGradientBackground();

      particles.forEach(particle => {
        particle.update();
        particle.draw();
      });

      // Draw connections
      particles.forEach((p1, i) => {
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p1.x - p2.x;
          const dy = p1.y - p2.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < 100) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(100, 149, 237, ${0.15 * (1 - distance / 100)})`;
            ctx.lineWidth = 0.5;
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
          }
        }
      });

      animationFrameId = requestAnimationFrame(animate);
    };

    const handleMouseMove = (event: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseRef.current = {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top
      };
    };

    const handleTouchMove = (event: TouchEvent) => {
      event.preventDefault();
      const rect = canvas.getBoundingClientRect();
      mouseRef.current = {
        x: event.touches[0].clientX - rect.left,
        y: event.touches[0].clientY - rect.top
      };
    };

    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('touchmove', handleTouchMove, { passive: false });
    window.addEventListener('resize', init);

    init();
    animate();

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      window.removeEventListener('resize', init);
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('touchmove', handleTouchMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, [isButtonHovered]);

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden">
      <canvas
        ref={canvasRef}
        className="absolute inset-0 z-0 touch-none"
      />

      <div className="relative z-10 text-center">
        <div className="flex justify-center mb-8">
          <Bot size={120} className="text-white animate-pulse" />
        </div>
        <h1 className="text-6xl font-bold text-white mb-4 tracking-tight animate-fade-in relative">
          <span className="inline-block animate-title-glow">Welcome to ODIN Chatbot</span>
        </h1>
        <p className="text-2xl text-gray-300 mb-12 font-light tracking-wide animate-subtitle-slide">
          Your intelligent assistant from MINERVA
        </p>
        <button
          onClick={onStart}
          onMouseEnter={() => setIsButtonHovered(true)}
          onMouseLeave={() => setIsButtonHovered(false)}
          className="bg-white text-[#343541] px-8 py-4 rounded-lg font-semibold text-xl 
                     flex items-center gap-2 mx-auto transition-all duration-300
                     hover:bg-opacity-90 hover:shadow-[0_0_30px_rgba(255,255,255,0.3)]
                     transform hover:scale-105"
        >
          Let's Get Started
          <ArrowRight size={24} />
        </button>
      </div>

      <footer className="absolute bottom-4 text-gray-400 w-full text-center">
        © 2024 AstraeusNextGen. All rights reserved.
      </footer>
    </div>
  );
}