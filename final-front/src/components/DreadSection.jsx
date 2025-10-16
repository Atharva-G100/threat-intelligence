import React, { useState } from 'react'
import { motion } from 'framer-motion'

const DreadSection = () => {
  const [dreadValues, setDreadValues] = useState({
    damage: '',
    reproducibility: '',
    exploitability: '',
    affected_users: '',
    discoverability: ''
  })
  const [score, setScore] = useState(null)
  const [error, setError] = useState(null)

  const handleChange = (field, value) => {
    const numericValue = Number(value)
    if (numericValue >= 0 && numericValue <= 10) {
      setDreadValues(prev => ({ ...prev, [field]: numericValue }))
    }
  }

  const handleSubmit = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/dread', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(dreadValues),
      })
      if (!response.ok) throw new Error('Failed to calculate DREAD score')
      const data = await response.json()
      setScore(data.score)
      setError(null)
    } catch (err) {
      console.error(err)
      setError('Something went wrong while calculating the DREAD score.')
      setScore(null)
    }
  }

  return (
    <motion.section
      className="dread-section"
      id="dread"
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
          <h2 className="section-title">Overall DREAD Scoring</h2>
          <p className="section-subtitle">Score your system’s overall risk level</p>
        </motion.div>

        <motion.div
          className="results-card card"
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          viewport={{ once: true }}
          whileHover={{ y: -5, boxShadow: '0 8px 40px rgba(57, 255, 20, 0.1)' }}
        >
          <div className="table-wrapper">
            <table className="results-table">
              <thead>
                <tr className="results-grid">
                  <th>Damage</th>
                  <th>Reproducibility</th>
                  <th>Exploitability</th>
                  <th>Affected Users</th>
                  <th>Discoverability</th>
                </tr>
              </thead>
              <tbody>
                <tr className="results-grid">
                  {['damage', 'reproducibility', 'exploitability', 'affected_users', 'discoverability'].map(field => (
                    <td key={field}>
                      <input
                        type="number"
                        min="0"
                        max="10"
                        value={dreadValues[field]}
                        onChange={(e) => handleChange(field, e.target.value)}
                        style={{ width: '50px' }}
                      />
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>

          <div style={{ textAlign: 'center', marginTop: '1rem' }}>
            <button className="btn btn--primary" onClick={handleSubmit}>
              Calculate Overall DREAD Score
            </button>
          </div>

          {score !== null && (
            <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '1.25rem', fontWeight: 'bold' }}>
              🔐 Your system’s overall DREAD score: <span style={{ color: '#39FF14' }}>{score.toFixed(2)}</span>
            </div>
          )}

          {error && (
            <div style={{ marginTop: '1rem', textAlign: 'center', color: 'red' }}>
              {error}
            </div>
          )}
        </motion.div>
      </div>
    </motion.section>
  )
}

export default DreadSection
