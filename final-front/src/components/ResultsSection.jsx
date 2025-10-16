import { motion, AnimatePresence } from 'framer-motion'
import { useStrideStore } from '../store/strideStore'

const ResultsSection = () => {
  const { threats } = useStrideStore()

  return (
    <motion.section 
      className="results-section"
      id="threats"
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
          <h2 className="section-title">Threat Analysis Results</h2>
          <p className="section-subtitle">Identified security vulnerabilities and recommendations</p>
        </motion.div>

        <motion.div 
          className="results-card card"
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          viewport={{ once: true }}
          whileHover={{ y: -5, boxShadow: "0 8px 40px rgba(57, 255, 20, 0.1)" }}
        >
          <div className="table-wrapper">
            <table className="results-table">
              <thead>
                <tr className="results-grid">
                  <th>Component</th>
                  <th>Threat Type</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {threats.length === 0 ? (
                    <motion.tr
                      className="results-grid"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                    >
                      <td colSpan="3" style={{ textAlign: 'center', opacity: 0.6, gridColumn: '1 / -1' }}>
                        No threats analyzed yet. Enter a system description above to begin.
                      </td>
                    </motion.tr>
                  ) : (
                    threats.map((threat, index) => (
                      <motion.tr
                        key={index}
                        className="results-grid"
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.5, delay: index * 0.1 }}
                        whileHover={{ backgroundColor: "rgba(57, 255, 20, 0.05)" }}
                      >
                        <td>{threat.component}</td>
                        <td>
                          <motion.span 
                            className="threat-type"
                            initial={{ scale: 0.9 }}
                            animate={{ scale: 1 }}
                            transition={{ duration: 0.3 }}
                          >
                            {threat.type}
                          </motion.span>
                        </td>
                        <td>{threat.description}</td>
                      </motion.tr>
                    ))
                  )}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </motion.div>
      </div>
    </motion.section>
  )
}

export default ResultsSection