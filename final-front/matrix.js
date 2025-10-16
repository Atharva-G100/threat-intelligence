(function() {
    let idleTimer;
    const tsBg = document.getElementById('tsBg');
    const isReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const isMobile = window.innerWidth < 768;
    
    // Determine particle count based on device and accessibility preferences
    let particleCount = 120; // Desktop default
    if (isReducedMotion) {
        particleCount = 20;
    } else if (isMobile) {
        particleCount = 48; // Mobile count
    }
    
    // Initialize tsParticles
    tsParticles.load("tsBg", {
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
    });

    // Mouse movement tracking for cursor spotlight halo
    document.addEventListener('mousemove', function(e) {
        if (isReducedMotion) return;
        
        const x = (e.clientX / window.innerWidth * 100);
        const y = (e.clientY / window.innerHeight * 100);
        
        tsBg.style.setProperty('--mx', x + '%');
        tsBg.style.setProperty('--my', y + '%');
        tsBg.classList.add('is-active');
        
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            tsBg.classList.remove('is-active');
        }, 1800);
    });
})();