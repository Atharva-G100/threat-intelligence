import React, { useEffect, useRef, useState } from 'react'
import Particles from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'

const MatrixSpotlight = () => {
  const [isActive, setIsActive] = useState(false)
  const idleTimerRef = useRef<number>()
  const containerRef = useRef<HTMLDivElement>(null)
  
  const isReducedMotion = typeof window !== 'undefined' && 
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const isMobile = typeof window !== 'undefined' && window.innerWidth < 768

  // Determine particle count and bubble distance based on device and accessibility preferences
  const particleCount = isReducedMotion ? 20 : (isMobile ? 48 : 120)
  const bubbleDistance = isMobile ? 130 : 200

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (isReducedMotion) return
      
      const container = containerRef.current
      if (!container) return
      
      const x = (e.clientX / window.innerWidth) * 100
      const y = (e.clientY / window.innerHeight) * 100
      
      document.documentElement.style.setProperty('--mx', `${x}%`)
      document.documentElement.style.setProperty('--my', `${y}%`)
      
      setIsActive(true)
      
      clearTimeout(idleTimerRef.current)
      idleTimerRef.current = setTimeout(() => {
        setIsActive(false)
      }, 1800)
    }

    document.addEventListener('mousemove', handleMouseMove)
    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      clearTimeout(idleTimerRef.current)
    }
  }, [isReducedMotion])

  const particlesInit = async (engine: any) => {
    await loadSlim(engine)
  }

  const options: any = {
    detectRetina: true,
    pauseOnBlur: true,
    particles: {
      number: {
        value: particleCount,
        density: {
          enable: true,
          value_area: 800
        }
      },
      color: {
        value: "#39FF14"
      },
      shape: {
        type: "char",
        character: {
          value: ["0", "1"],
          font: "monospace",
          style: "",
          weight: "400",
          fill: true
        }
      },
      opacity: {
        value: isReducedMotion ? 0.03 : 0.04,
        random: false
      },
      size: {
        value: 13,
        random: {
          enable: true,
          minimumValue: 12
        },
        animation: {
          enable: false
        }
      },
      move: {
        enable: false
      }
    },
    interactivity: {
      detectsOn: "window" as any,
      events: {
        onhover: {
          enable: !isReducedMotion,
          mode: "bubble",
          parallax: {
            enable: !isReducedMotion,
            force: 35,
            smooth: 10
          }
        }
      },
      modes: {
        bubble: {
          distance: bubbleDistance,
          duration: 0.45,
          opacity: 0.45,
          size: 16,
          color: "#39FF14"
        }
      }
    }
  }

  // Update tsBg element class when active state changes
  useEffect(() => {
    const tsBgElement = document.getElementById('tsBg');
    if (tsBgElement) {
      tsBgElement.className = isActive ? 'is-active' : '';
    }
  }, [isActive]);

  return (
    <Particles
      id="matrix-particles"
      loaded={particlesInit}
      options={options}
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%'
      }}
    />
  )
}

export default MatrixSpotlight