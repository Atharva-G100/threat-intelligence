import { motion } from 'framer-motion'

const Footer = () => {
  return (
    <motion.footer 
      className="footer"
      initial={{ opacity: 0, y: 50 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.8 }}
      viewport={{ once: true }}
    >
      <div className="container">
        <div className="footer-content">
          <motion.div 
            className="footer-brand"
            whileHover={{ scale: 1.05 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <svg className="footer-logo" width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
              <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
              <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
            </svg>
            <span>STRIDE Analyzer</span>
          </motion.div>
          <div className="footer-links">
            <motion.a 
              href="#" 
              className="footer-link"
              whileHover={{ scale: 1.05, color: "#39FF14" }}
              transition={{ duration: 0.2 }}
            >
              Documentation
            </motion.a>
            <motion.a 
              href="#" 
              className="footer-link"
              whileHover={{ scale: 1.05, color: "#39FF14" }}
              transition={{ duration: 0.2 }}
            >
              Security
            </motion.a>
            <motion.a 
              href="#" 
              className="footer-link"
              whileHover={{ scale: 1.05, color: "#39FF14" }}
              transition={{ duration: 0.2 }}
            >
              Support
            </motion.a>
          </div>
        </div>
      </div>
    </motion.footer>
  )
}

export default Footer