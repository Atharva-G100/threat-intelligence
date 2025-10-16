import { motion } from 'framer-motion'

const HeroSection = () => {
  return (
    <motion.section 
      className="hero-section parallax parallax-section"
      initial={{ opacity: 0, y: 50 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 1, delay: 0.2 }}
    >
      <div className="parallax-bg bg-layer starfield" />
      <div className="parallax-bg bg-layer grid-overlay" />
      <div className="parallax-bg bg-layer node-network">
        <svg className="network-svg" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
          <g className="nodes">
            <circle className="node node-1" cx="200" cy="150" r="4"/>
            <circle className="node node-2" cx="400" cy="200" r="3"/>
            <circle className="node node-3" cx="600" cy="100" r="5"/>
            <circle className="node node-4" cx="800" cy="180" r="3"/>
            <circle className="node node-5" cx="1000" cy="120" r="4"/>
            <circle className="node node-6" cx="300" cy="400" r="3"/>
            <circle className="node node-7" cx="700" cy="350" r="4"/>
            <circle className="node node-8" cx="900" cy="450" r="3"/>
          </g>
          <g className="connections">
            <line className="connection" x1="200" y1="150" x2="400" y2="200"/>
            <line className="connection" x1="400" y1="200" x2="600" y2="100"/>
            <line className="connection" x1="600" y1="100" x2="800" y2="180"/>
            <line className="connection" x1="800" y1="180" x2="1000" y2="120"/>
            <line className="connection" x1="300" y1="400" x2="700" y2="350"/>
            <line className="connection" x1="700" y1="350" x2="900" y2="450"/>
            <line className="connection" x1="400" y1="200" x2="300" y2="400"/>
          </g>
        </svg>
      </div>
      
      <div className="container">
        <div className="hero-content">
          <motion.h1 
            className="hero-title"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
          >
            STRIDE Threat Analyzer
          </motion.h1>
          <motion.p 
            className="hero-subtitle"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.6 }}
          >
            Advanced cybersecurity threat modeling and analysis platform
          </motion.p>
          
          <motion.div 
            className="status-strip"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.8, delay: 0.8 }}
          >
            <div className="status-cards">
              <motion.div 
                className="status-card"
                whileHover={{ scale: 1.05, y: -2 }}
                transition={{ type: "spring", stiffness: 300 }}
              >
                <div className="status-value">127</div>
                <div className="status-label">Threats Blocked</div>
              </motion.div>
              <motion.div 
                className="status-card"
                whileHover={{ scale: 1.05, y: -2 }}
                transition={{ type: "spring", stiffness: 300 }}
              >
                <div className="status-value">12ms</div>
                <div className="status-label">Latency</div>
              </motion.div>
              <motion.div 
                className="status-card"
                whileHover={{ scale: 1.05, y: -2 }}
                transition={{ type: "spring", stiffness: 300 }}
              >
                <div className="status-value">99.9%</div>
                <div className="status-label">Uptime</div>
              </motion.div>
              <motion.div 
                className="status-card"
                whileHover={{ scale: 1.05, y: -2 }}
                transition={{ type: "spring", stiffness: 300 }}
              >
                <div className="status-value">Active</div>
                <div className="status-label">System Status</div>
              </motion.div>
            </div>
          </motion.div>
        </div>
      </div>
    </motion.section>
  )
}

export default HeroSection