import React from 'react'
import ReactDOM from 'react-dom/client'
import { createPortal } from 'react-dom'
import MatrixSpotlight from './components/MatrixSpotlight'
import BackgroundFX from './components/BackgroundFX'
import CursorFX from './components/CursorFX'
import App from './App'
import './index.css'

const AppWithLayers = () => {
  const tsBgElement = document.getElementById('tsBg')
  
  return (
    <React.StrictMode>
      {tsBgElement && createPortal(<MatrixSpotlight />, tsBgElement)}
      <BackgroundFX />
      <CursorFX />
      <App />
    </React.StrictMode>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(<AppWithLayers />)