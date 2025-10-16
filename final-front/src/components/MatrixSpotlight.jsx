import { useEffect, useRef, useState } from 'react'
import Particles from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'
import classNames from 'classnames'

const MatrixSpotlight = () => {
  const [isActive, setIsActive] = useState(false)
  const idleTimerRef = useRef()
  const containerRef = useRef()
  
  const isReducedMotion = typeof window !== 'undefined' && 
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const isMobile = typeof window !== 'undefined' && window.innerWidth < 768

  // Determine particle count based on device and accessibility preferences
  const particleCount = isReducedMotion ? 20 : (isMobile ? 48 : 120)

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (isReducedMotion) return
      
      const container = containerRef.current
      if (!container) return
      
      const x = (e.clientX / window.innerWidth) * 100
      const y = (e.clientY / window.innerHeight) * 100
      
      container.style.setProperty('--mx', `${x}%`)
      container.style.setProperty('--my', `${y}%`)
      
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

  const particlesInit = async (engine) => {
    await loadSlim(engine)
  }

  const options = {
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
          fill: "true"
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
      detectsOn: "window",
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
          distance: isMobile ? 130 : 200,
          duration: 0.45,
          opacity: 0.45,
          size: 16,
          color: "#39FF14"
        }
      }
    }
  }

  return (
    <div
      ref={containerRef}
      className={classNames('matrix-spotlight', {
        'is-active': isActive
      })}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
        opacity: 0.04,
        transition: 'opacity 0.35s ease',
        filter: 'drop-shadow(0 0 1px rgba(57, 255, 20, 0.25))'
      }}
    >
      <Particles
        id="matrix-particles"
        init={particlesInit}
        options={options}
      />
      <div className="matrix-halo" />
    </div>
  )
}

export default MatrixSpotlight