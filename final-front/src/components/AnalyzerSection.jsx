import { useState } from 'react'
import { motion } from 'framer-motion'
import { useStrideStore } from '../store/strideStore'

const AnalyzerSection = () => {
  const [flowInput, setFlowInput] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [isGeneratingDFD, setIsGeneratingDFD] = useState(false)
  const [dfdImageUrl, setDfdImageUrl] = useState(null)
  const { setThreats } = useStrideStore()

  const handleAnalyze = async () => {
    if (!flowInput.trim()) return

    setIsAnalyzing(true)
    setDfdImageUrl(null)

    try {
      const response = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flow: flowInput }),
      })

      if (response.ok) {
        const data = await response.json()
        setThreats(data.threats || [])
      } else {
        console.error('Analysis failed')
        setThreats([])
      }
    } catch (error) {
      console.error('Error analyzing threats:', error)
      setThreats([])
    } finally {
      setIsAnalyzing(false)
    }
  }

  const generateDFD = async () => {
    if (!flowInput.trim()) return

    setIsGeneratingDFD(true)
    setDfdImageUrl(null)

    let dfdPayload
    try {
      // Expect user to paste JSON describing nodes + flows
      dfdPayload = JSON.parse(flowInput)
    } catch (err) {
      console.error("❌ Invalid JSON input for DFD:", err)
      setIsGeneratingDFD(false)
      return
    }

    try {
      const response = await fetch('http://127.0.0.1:8000/generate_dfd', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(dfdPayload),
      })

      if (!response.ok) {
        console.error('Failed to generate DFD')
        setDfdImageUrl(null)
        return
      }

      const blob = await response.blob()
      const imageUrl = URL.createObjectURL(blob)
      setDfdImageUrl(imageUrl)
    } catch (error) {
      console.error('Error generating DFD:', error)
      setDfdImageUrl(null)
    } finally {
      setIsGeneratingDFD(false)
    }
  }

  return (
    <motion.section
      className="analyzer-section"
      id="analyzer"
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
          <h2 className="section-title">System Analysis</h2>
          <p className="section-subtitle">Describe your system architecture for comprehensive threat analysis</p>
        </motion.div>

        <motion.div
          className="analyzer-card card"
          initial={{ opacity: 0, scale: 0.95 }}
          whileInView={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          viewport={{ once: true }}
          whileHover={{ y: -5, boxShadow: '0 8px 40px rgba(57, 255, 20, 0.1)' }}
        >
          <div className="input-wrapper">
            <label htmlFor="flowInput" className="input-label">System Flow Description / JSON for DFD</label>
            <motion.textarea
              id="flowInput"
              className="flow-input"
              placeholder='Example: {"nodes":[{"id":"User","type":"external_entity"}],"flows":[{"source":"User","target":"AuthAPI"}]}'
              rows="8"
              value={flowInput}
              onChange={(e) => setFlowInput(e.target.value)}
              whileFocus={{ scale: 1.01, boxShadow: '0 0 20px rgba(57, 255, 20, 0.2)' }}
              transition={{ type: 'spring', stiffness: 300 }}
            />
          </div>

          <div className="analyzer-actions" style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
            <motion.button
              className="btn btn--primary"
              onClick={handleAnalyze}
              disabled={isAnalyzing || !flowInput.trim()}
              whileHover={{
                scale: 1.05,
                boxShadow: '0 0 25px rgba(57, 255, 20, 0.4)',
              }}
              whileTap={{ scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 300 }}
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze Threats'}
            </motion.button>

            <motion.button
              className="btn btn--secondary"
              onClick={generateDFD}
              disabled={isGeneratingDFD || !flowInput.trim()}
              whileHover={{
                scale: 1.05,
                boxShadow: '0 0 25px rgba(20, 120, 255, 0.6)',
              }}
              whileTap={{ scale: 0.98 }}
              transition={{ type: 'spring', stiffness: 300 }}
            >
              {isGeneratingDFD ? 'Generating DFD...' : 'Generate DFD'}
            </motion.button>
          </div>

          {dfdImageUrl && (
            <div style={{ marginTop: '1.5rem', textAlign: 'center' }}>
              <h4>Generated Data Flow Diagram</h4>
              <img
                src={dfdImageUrl}
                alt="Data Flow Diagram"
                style={{ maxWidth: '100%', borderRadius: '8px', boxShadow: '0 0 10px rgba(0,0,0,0.2)' }}
              />
              <br />
              <a
                href={dfdImageUrl}
                download="data_flow_diagram.png"
                style={{
                  display: 'inline-block',
                  marginTop: '1rem',
                  padding: '0.5rem 1rem',
                  backgroundColor: '#398c15',
                  color: 'white',
                  borderRadius: '4px',
                  textDecoration: 'none',
                  cursor: 'pointer',
                }}
              >
                Download Diagram
              </a>
            </div>
          )}
        </motion.div>
      </div>
    </motion.section>
  )
}

export default AnalyzerSection
