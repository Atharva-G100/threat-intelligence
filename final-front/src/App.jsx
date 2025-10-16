import { useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import Lenis from 'lenis'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
// MatrixSpotlight and BackgroundFX now rendered in main.tsx
import Navigation from './components/Navigation'
import HeroSection from './components/HeroSection'
import AnalyzerSection from './components/AnalyzerSection'
import ResultsSection from './components/ResultsSection'
import DreadSection from './components/DreadSection'
import SecuritySection from './components/SecuritySection'
import Footer from './components/Footer'
import './App.css'

// Register GSAP plugins
gsap.registerPlugin(ScrollTrigger)

function App() {
  const lenisRef = useRef()

  useEffect(() => {
    // Initialize Lenis for smooth scrolling
    const lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smooth: true
    })

    lenisRef.current = lenis

    // Integrate Lenis with GSAP ScrollTrigger
    lenis.on('scroll', ScrollTrigger.update)

    gsap.ticker.add((time) => {
      lenis.raf(time * 1000)
    })

    gsap.ticker.lagSmoothing(0)

    // Parallax animations
    gsap.to('.parallax-bg', {
      yPercent: -50,
      ease: 'none',
      scrollTrigger: {
        trigger: '.parallax-section',
        start: 'top bottom',
        end: 'bottom top',
        scrub: true
      }
    })

    return () => {
      lenis.destroy()
      ScrollTrigger.getAll().forEach(trigger => trigger.kill())
    }
  }, [])

  return (
    <>
      <Navigation />
      
      <motion.main
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.8 }}
      >
        <HeroSection />
        <AnalyzerSection />
        <ResultsSection />
        <DreadSection />
        <SecuritySection />
      </motion.main>
      
      <Footer />
    </>
  )
}

export default App