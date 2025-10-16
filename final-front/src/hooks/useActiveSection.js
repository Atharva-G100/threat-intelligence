import { useState, useEffect } from 'react'

const useActiveSection = () => {
  const [activeSection, setActiveSection] = useState('analyzer')

  useEffect(() => {
    const sections = ['analyzer', 'threats', 'security']
    const sectionElements = sections.map(id => document.getElementById(id)).filter(Boolean)

    if (sectionElements.length === 0) return

    const observer = new IntersectionObserver(
      (entries) => {
        // Find the entry with the highest intersection ratio
        let maxEntry = entries[0]
        entries.forEach(entry => {
          if (entry.intersectionRatio > maxEntry.intersectionRatio) {
            maxEntry = entry
          }
        })

        if (maxEntry.intersectionRatio > 0) {
          setActiveSection(maxEntry.target.id)
        }
      },
      {
        rootMargin: '-45% 0px -45% 0px',
        threshold: [0, 0.25, 0.5, 0.75, 1]
      }
    )

    sectionElements.forEach(element => {
      observer.observe(element)
    })

    return () => {
      observer.disconnect()
    }
  }, [])

  return activeSection
}

export default useActiveSection