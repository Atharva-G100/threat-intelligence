import { motion } from 'framer-motion'
import classNames from 'classnames'
import useNavSpy from '../hooks/NavSpy'

const Navigation = () => {
  const activeSection = useNavSpy()
  return (
    <motion.nav 
      className="nav-sticky"
      initial={{ y: -100, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.8, ease: "easeOut" }}
    >
      <div className="nav-container">
        <motion.div 
          className="nav-logo"
          whileHover={{ scale: 1.05 }}
          transition={{ type: "spring", stiffness: 300 }}
        >
          <svg className="logo-icon" width="24" height="24" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
            <path d="M2 17L12 22L22 17" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
            <path d="M2 12L12 17L22 12" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
          </svg>
          <span className="logo-text">STRIDE Analyzer</span>
        </motion.div>
        <div className="nav-links nav">
          <motion.a 
            href="#analyzer" 
            className={classNames('nav-link', { 'is-active': activeSection === 'analyzer' })}
            aria-current={activeSection === 'analyzer' ? 'page' : undefined}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Analyzer
          </motion.a>
          <motion.a 
            href="#threats" 
            className={classNames('nav-link', { 'is-active': activeSection === 'threats' })}
            aria-current={activeSection === 'threats' ? 'page' : undefined}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Threats
          </motion.a>
          <motion.a 
            href="#security" 
            className={classNames('nav-link', { 'is-active': activeSection === 'security' })}
            aria-current={activeSection === 'security' ? 'page' : undefined}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            Security
          </motion.a>
        </div>
        <div className="nav-cta">
          <motion.button 
            className="btn btn--nav"
            whileHover={{ scale: 1.05, boxShadow: "0 0 20px rgba(57, 255, 20, 0.3)" }}
            whileTap={{ scale: 0.95 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            Dashboard
          </motion.button>
        </div>
      </div>
    </motion.nav>
  )
}

export default Navigation