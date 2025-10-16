// CDN fallback for Matrix Spotlight if React wrapper fails
(() => {
  const isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const isMobile = window.innerWidth < 768
  
  if (isReducedMotion) return
  
  const particleCount = isMobile ? 48 : 120
  const bubbleDistance = isMobile ? 130 : 200
  
  // Create container if it doesn't exist
  let container = document.getElementById('tsBg')
  if (!container) {
    container = document.createElement('div')
    container.id = 'tsBg'
    container.style.cssText = `
      position: fixed;
      inset: 0;
      z-index: 0;
      pointer-events: none;
      opacity: 0.04;
      transition: opacity 0.35s ease;
    `
    document.body.appendChild(container)
  }
  
  // Initialize tsParticles
  tsParticles.load('tsBg', {
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
        value: 0.04,
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
          enable: true,
          mode: "bubble",
          parallax: {
            enable: true,
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
  })
  
  // Mouse movement handling for cursor halo
  let isActive = false
  let idleTimer
  
  const handleMouseMove = (e) => {
    const x = (e.clientX / window.innerWidth) * 100
    const y = (e.clientY / window.innerHeight) * 100
    
    document.documentElement.style.setProperty('--mx', `${x}%`)
    document.documentElement.style.setProperty('--my', `${y}%`)
    
    container.classList.add('is-active')
    isActive = true
    
    clearTimeout(idleTimer)
    idleTimer = setTimeout(() => {
      container.classList.remove('is-active')
      isActive = false
    }, 1800)
  }
  
  document.addEventListener('mousemove', handleMouseMove)
})()