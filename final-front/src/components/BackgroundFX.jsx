import { useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Lenis from 'lenis'

gsap.registerPlugin(ScrollTrigger)

const BackgroundFX = () => {
  const lenisRef = useRef()
  const gridRef = useRef()
  const nodeRef = useRef()

  useEffect(() => {
    // Initialize Lenis smooth scrolling
    const lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      direction: 'vertical',
      gestureDirection: 'vertical',
      smooth: true,
      mouseMultiplier: 1,
      smoothTouch: false,
      touchMultiplier: 2,
      infinite: false,
    })

    lenisRef.current = lenis

    function raf(time) {
      lenis.raf(time)
      requestAnimationFrame(raf)
    }

    requestAnimationFrame(raf)

    // Connect Lenis to GSAP ScrollTrigger
    lenis.on('scroll', ScrollTrigger.update)

    gsap.ticker.lagSmoothing(0)

    // Create parallax animations
    if (gridRef.current) {
      gsap.to(gridRef.current, {
        yPercent: -50,
        ease: 'none',
        scrollTrigger: {
          trigger: document.body,
          start: 'top bottom',
          end: 'bottom top',
          scrub: true
        }
      })
    }

    if (nodeRef.current) {
      gsap.to(nodeRef.current, {
        yPercent: -25,
        ease: 'none',
        scrollTrigger: {
          trigger: document.body,
          start: 'top bottom',
          end: 'bottom top',
          scrub: true
        }
      })
    }

    return () => {
      lenis.destroy()
      ScrollTrigger.getAll().forEach(trigger => trigger.kill())
    }
  }, [])

  return (
    <div className="background-fx">
      {/* Grid overlay */}
      <div 
        ref={gridRef}
        className="grid-overlay"
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: -2,
          pointerEvents: 'none',
          opacity: 0.15,
          background: `
            linear-gradient(rgba(57, 255, 20, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(57, 255, 20, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px'
        }}
      />
      
      {/* Node network */}
      <div 
        ref={nodeRef}
        className="node-network"
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: -1,
          pointerEvents: 'none',
          opacity: 0.08
        }}
      >
        <svg
          width="100%"
          height="100%"
          viewBox="0 0 1920 1080"
          preserveAspectRatio="xMidYMid slice"
        >
          <defs>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
              <feMerge> 
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          
          {/* Network nodes */}
          {Array.from({ length: 12 }, (_, i) => (
            <circle
              key={i}
              cx={150 + (i % 4) * 450}
              cy={200 + Math.floor(i / 4) * 280}
              r="3"
              fill="#39FF14"
              filter="url(#glow)"
            />
          ))}
          
          {/* Connection lines */}
          <g stroke="#39FF14" strokeWidth="1" opacity="0.6">
            <line x1="150" y1="200" x2="600" y2="200" />
            <line x1="600" y1="200" x2="1050" y2="200" />
            <line x1="1050" y1="200" x2="1500" y2="200" />
            <line x1="150" y1="480" x2="600" y2="480" />
            <line x1="600" y1="480" x2="1050" y2="480" />
            <line x1="1050" y1="480" x2="1500" y2="480" />
            <line x1="150" y1="760" x2="600" y2="760" />
            <line x1="600" y1="760" x2="1050" y2="760" />
            <line x1="1050" y1="760" x2="1500" y2="760" />
            <line x1="150" y1="200" x2="150" y2="480" />
            <line x1="600" y1="200" x2="600" y2="480" />
            <line x1="1050" y1="200" x2="1050" y2="480" />
            <line x1="1500" y1="200" x2="1500" y2="480" />
            <line x1="150" y1="480" x2="150" y2="760" />
            <line x1="600" y1="480" x2="600" y2="760" />
            <line x1="1050" y1="480" x2="1050" y2="760" />
            <line x1="1500" y1="480" x2="1500" y2="760" />
          </g>
        </svg>
      </div>
    </div>
  )
}

export default BackgroundFX