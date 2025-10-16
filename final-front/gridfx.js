// Grid FX - Canvas-based grid with moving tracers
(() => {
  const canvas = document.getElementById('gridFx');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  let width, height;
  let cellSize = 66; // 60-72px cell size
  let tracers = [];
  let isReducedMotion = false;
  let isMobile = false;
  let animationId;
  let lastTime = 0;
  
  // Check accessibility and device preferences
  const updatePreferences = () => {
    isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    isMobile = window.innerWidth < 768;
    cellSize = isMobile ? 60 : 66;
  };
  
  // Resize handler
  const resize = () => {
    updatePreferences();
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * window.devicePixelRatio;
    canvas.height = height * window.devicePixelRatio;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    
    // Recreate tracers with new grid
    initTracers();
  };
  
  // Tracer class
  class Tracer {
    constructor() {
      this.reset();
    }
    
    reset() {
      // Pick random edge (horizontal or vertical)
      this.isHorizontal = Math.random() > 0.5;
      this.length = 80 + Math.random() * 80; // 80-160px
      this.opacity = 0.3 + Math.random() * 0.3; // 0.3-0.6
      this.speed = (120 + Math.random() * 60) * (isMobile ? 0.5 : 1); // 120-180px/s
      
      if (this.isHorizontal) {
        // Horizontal tracer
        this.y = Math.floor(Math.random() * (height / cellSize)) * cellSize;
        this.x = -this.length;
        this.direction = 1;
      } else {
        // Vertical tracer
        this.x = Math.floor(Math.random() * (width / cellSize)) * cellSize;
        this.y = -this.length;
        this.direction = 1;
      }
    }
    
    update(dt) {
      if (this.isHorizontal) {
        this.x += this.speed * dt * this.direction;
        if (this.x > width + this.length) {
          this.reset();
        }
      } else {
        this.y += this.speed * dt * this.direction;
        if (this.y > height + this.length) {
          this.reset();
        }
      }
    }
    
    draw() {
      ctx.save();
      ctx.globalCompositeOperation = 'lighter';
      
      const gradient = this.isHorizontal
        ? ctx.createLinearGradient(this.x, this.y, this.x + this.length, this.y)
        : ctx.createLinearGradient(this.x, this.y, this.x, this.y + this.length);
      
      gradient.addColorStop(0, `rgba(57, 255, 20, 0)`);
      gradient.addColorStop(0.5, `rgba(57, 255, 20, ${this.opacity})`);
      gradient.addColorStop(1, `rgba(57, 255, 20, 0)`);
      
      // Draw 3 strokes for glow effect
      ctx.strokeStyle = gradient;
      
      // Core stroke (1px)
      ctx.lineWidth = 1;
      ctx.beginPath();
      if (this.isHorizontal) {
        ctx.moveTo(this.x, this.y);
        ctx.lineTo(this.x + this.length, this.y);
      } else {
        ctx.moveTo(this.x, this.y);
        ctx.lineTo(this.x, this.y + this.length);
      }
      ctx.stroke();
      
      // Outer glow (2px at lower alpha)
      ctx.globalAlpha = 0.3;
      ctx.lineWidth = 2;
      ctx.stroke();
      
      ctx.restore();
    }
  }
  
  // Initialize tracers
  const initTracers = () => {
    const tracerCount = isReducedMotion ? 0 : (isMobile ? 8 : 14); // 10-16 range
    tracers = [];
    for (let i = 0; i < tracerCount; i++) {
      tracers.push(new Tracer());
    }
  };
  
  // Draw static grid
  const drawGrid = () => {
    ctx.save();
    ctx.strokeStyle = `rgba(57, 255, 20, 0.06)`;
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    
    // Vertical lines
    for (let x = 0; x <= width; x += cellSize) {
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
    }
    
    // Horizontal lines
    for (let y = 0; y <= height; y += cellSize) {
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
    }
    
    ctx.stroke();
    ctx.restore();
  };
  
  // Animation loop
  const animate = (currentTime) => {
    if (document.hidden) {
      animationId = requestAnimationFrame(animate);
      return;
    }
    
    const dt = Math.min((currentTime - lastTime) / 1000, 1/30); // Cap at 30fps
    lastTime = currentTime;
    
    // Clear canvas
    ctx.clearRect(0, 0, width, height);
    
    // Draw static grid
    drawGrid();
    
    // Update and draw tracers (skip if reduced motion)
    if (!isReducedMotion) {
      tracers.forEach(tracer => {
        tracer.update(dt);
        tracer.draw();
      });
    }
    
    animationId = requestAnimationFrame(animate);
  };
  
  // Start
  const init = () => {
    resize();
    animate(0);
  };
  
  // Event listeners
  window.addEventListener('resize', resize);
  window.addEventListener('load', init);
  
  // Cleanup
  window.addEventListener('beforeunload', () => {
    if (animationId) {
      cancelAnimationFrame(animationId);
    }
  });
  
  // Start immediately if DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();