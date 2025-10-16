// Network Links - tsParticles configuration for moving nodes with connections
(() => {
  const container = document.getElementById('tsLinks');
  if (!container || !window.tsParticles) {
    console.warn('tsParticles or container not available');
    return;
  }
  
  const isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isMobile = window.innerWidth < 768;
  
  const config = {
    detectRetina: true,
    pauseOnBlur: true,
    zLayers: 1,
    particles: {
      number: {
        value: isMobile ? 20 : 45,
        density: {
          enable: true,
          value_area: 1000
        }
      },
      color: {
        value: "#39FF14"
      },
      shape: {
        type: "circle"
      },
      opacity: {
        value: 0.25,
        random: false
      },
      size: {
        value: 2.5,
        random: {
          enable: true,
          minimumValue: 2
        }
      },
      links: {
        enable: true,
        distance: 140,
        color: "#39FF14",
        opacity: isReducedMotion ? 0.12 : 0.25,
        width: 1,
        triangles: {
          enable: false
        }
      },
      move: {
        enable: !isReducedMotion,
        speed: isReducedMotion ? 0 : (0.4 + Math.random() * 0.4), // 0.4-0.8
        direction: "none",
        random: true,
        straight: false,
        outModes: {
          default: "bounce"
        },
        attract: {
          enable: false
        }
      }
    },
    interactivity: {
      detectsOn: "window",
      events: {
        onhover: {
          enable: !isReducedMotion,
          mode: "grab",
          parallax: {
            enable: !isReducedMotion,
            force: 25,
            smooth: 12
          }
        },
        onclick: {
          enable: false
        },
        resize: true
      },
      modes: {
        grab: {
          distance: 160,
          links: {
            opacity: 0.4
          }
        }
      }
    }
  };
  
  // Initialize tsParticles
  const init = async () => {
    try {
      await tsParticles.load('tsLinks', config);
    } catch (error) {
      console.warn('Failed to load tsParticles:', error);
    }
  };
  
  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();