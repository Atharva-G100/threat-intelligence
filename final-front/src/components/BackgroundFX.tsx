import React, { useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Lenis from 'lenis'

gsap.registerPlugin(ScrollTrigger)

const BackgroundFX = () => {
  const lenisRef = useRef<Lenis>()
  const gridRef = useRef<HTMLDivElement>(null)
  const starsRef = useRef<HTMLDivElement>(null)
  const parallaxRef = useRef<HTMLDivElement>(null)

  const isReducedMotion = typeof window !== 'undefined' && 
    window.matchMedia('(prefers-reduced-motion: reduce)').matches

  useEffect(() => {
    if (isReducedMotion) return

    // Initialize Lenis smooth scrolling
    const lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
    } as any)

    lenisRef.current = lenis

    function raf(time: number) {
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
        yPercent: -30,
        ease: 'none',
        scrollTrigger: {
          trigger: document.body,
          start: 'top bottom',
          end: 'bottom top',
          scrub: true
        }
      })
    }

    if (starsRef.current) {
      gsap.to(starsRef.current, {
        yPercent: -20,
        ease: 'none',
        scrollTrigger: {
          trigger: document.body,
          start: 'top bottom',
          end: 'bottom top',
          scrub: true
        }
      })
    }

    // Mouse-reactive parallax
    const handleMouseMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth - 0.5) * 2
      const y = (e.clientY / window.innerHeight - 0.5) * 2
      
      document.documentElement.style.setProperty('--mouse-x', `${x * 10}px`)
      document.documentElement.style.setProperty('--mouse-y', `${y * 10}px`)
    }

    document.addEventListener('mousemove', handleMouseMove)

    return () => {
      lenis.destroy()
      ScrollTrigger.getAll().forEach(trigger => trigger.kill())
      document.removeEventListener('mousemove', handleMouseMove)
    }
  }, [isReducedMotion])

  if (isReducedMotion) return null

  return (
    <div className="background-fx">
      {/* Grid overlay */}
      <div 
        ref={gridRef}
        className="grid-overlay"
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: -3,
          pointerEvents: 'none',
          opacity: 0.08,
          background: `
            linear-gradient(rgba(57, 255, 20, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(57, 255, 20, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
          transform: 'translate3d(var(--mouse-x, 0), var(--mouse-y, 0), 0)'
        }}
      />
      
      {/* Stars field */}
      <div 
        ref={starsRef}
        className="stars-field"
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: -2,
          pointerEvents: 'none',
          opacity: 0.12,
          transform: 'translate3d(calc(var(--mouse-x, 0) * 0.5), calc(var(--mouse-y, 0) * 0.5), 0)'
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
              <feGaussianBlur stdDeviation="1" result="coloredBlur"/>
              <feMerge> 
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          
          {/* Generate star points */}
          {Array.from({ length: 24 }, (_, i) => (
            <circle
              key={i}
              cx={Math.random() * 1920}
              cy={Math.random() * 1080}
              r={Math.random() * 2 + 1}
              fill="#39FF14"
              filter="url(#glow)"
              opacity={Math.random() * 0.8 + 0.2}
            />
          ))}
          
          {/* Connection lines */}
          <g stroke="#39FF14" strokeWidth="0.5" opacity="0.3">
            {Array.from({ length: 8 }, (_, i) => (
              <line
                key={i}
                x1={200 + i * 200}
                y1="200"
                x2={200 + i * 200}
                y2="880"
              />
            ))}
            {Array.from({ length: 4 }, (_, i) => (
              <line
                key={i}
                x1="200"
                y1={200 + i * 200}
                x2="1720"
                y2={200 + i * 200}
              />
            ))}
          </g>
        </svg>
      </div>
    </div>
  )
}

export default BackgroundFX