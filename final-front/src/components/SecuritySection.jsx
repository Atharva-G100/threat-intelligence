import { motion } from 'framer-motion'

const SecuritySection = () => {
  return (
    <motion.section 
      className="security-section"
      id="security"
      initial={{ opacity: 0, y: 50 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8 }}
      viewport={{ once: true, amount: 0.3 }}
    >
      <div className="container">
        <motion.div 
          className="section-header"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2 }}
          viewport={{ once: true }}
        >
          <h2 className="section-title">Security Monitoring</h2>
          <p className="section-subtitle">Real-time threat detection and system integrity</p>
        </motion.div>

        <motion.div 
          className="security-grid"
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          viewport={{ once: true }}
        >
          <motion.div 
            className="security-card card"
            whileHover={{ y: -8, scale: 1.02, boxShadow: "0 12px 50px rgba(57, 255, 20, 0.15)" }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <div className="security-visual radar-container">
              <div className="radar-sweep"></div>
              <div className="radar-rings">
                <div className="radar-ring"></div>
                <div className="radar-ring"></div>
                <div className="radar-ring"></div>
              </div>
            </div>
            <motion.h3 
              className="security-title"
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
            >
              Threat Radar
            </motion.h3>
            <motion.p 
              className="security-desc"
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              transition={{ delay: 0.8 }}
            >
              360° monitoring
            </motion.p>
          </motion.div>

          <motion.div 
            className="security-card card"
            whileHover={{ y: -8, scale: 1.02, boxShadow: "0 12px 50px rgba(57, 255, 20, 0.15)" }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <motion.div 
              className="security-visual lock-container"
              whileHover={{ scale: 1.1 }}
              transition={{ type: "spring", stiffness: 300 }}
            >
              <svg className="lock-icon" width="48" height="48" viewBox="0 0 24 24" fill="none">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" stroke="currentColor" strokeWidth="2"/>
                <circle cx="12" cy="16" r="1" fill="currentColor"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="currentColor" strokeWidth="2"/>
              </svg>
            </motion.div>
            <motion.h3 
              className="security-title"
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
            >
              Data Protection
            </motion.h3>
            <motion.p 
              className="security-desc"
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              transition={{ delay: 0.8 }}
            >
              End-to-end encryption
            </motion.p>
          </motion.div>

          <motion.div 
            className="security-card card"
            whileHover={{ y: -8, scale: 1.02, boxShadow: "0 12px 50px rgba(57, 255, 20, 0.15)" }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <div className="security-visual matrix-container">
              <div className="matrix-rain">
                <motion.div 
                  className="matrix-column"
                  animate={{ y: ['-100px', '100px'] }}
                  transition={{ duration: 2, repeat: Infinity, delay: 0 }}
                />
                <motion.div 
                  className="matrix-column"
                  animate={{ y: ['-100px', '100px'] }}
                  transition={{ duration: 2, repeat: Infinity, delay: 0.5 }}
                />
                <motion.div 
                  className="matrix-column"
                  animate={{ y: ['-100px', '100px'] }}
                  transition={{ duration: 2, repeat: Infinity, delay: 1 }}
                />
                <motion.div 
                  className="matrix-column"
                  animate={{ y: ['-100px', '100px'] }}
                  transition={{ duration: 2, repeat: Infinity, delay: 1.5 }}
                />
                <motion.div 
                  className="matrix-column"
                  animate={{ y: ['-100px', '100px'] }}
                  transition={{ duration: 2, repeat: Infinity, delay: 2 }}
                />
              </div>
            </div>
            <motion.h3 
              className="security-title"
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
            >
              Code Analysis
            </motion.h3>
            <motion.p 
              className="security-desc"
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              transition={{ delay: 0.8 }}
            >
              Pattern recognition
            </motion.p>
          </motion.div>
        </motion.div>
      </div>
    </motion.section>
  )
}

export default SecuritySection