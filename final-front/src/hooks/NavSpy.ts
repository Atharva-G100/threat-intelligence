import { useState, useEffect } from 'react'

const useNavSpy = () => {
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

    // Handle hash changes and clicks
    const handleHashChange = () => {
      const hash = window.location.hash.slice(1)
      if (sections.includes(hash)) {
        setActiveSection(hash)
      }
    }

    const handleClick = (e: Event) => {
      const target = e.target as HTMLElement
      const link = target.closest('a[href^="#"]')
      if (link && link instanceof HTMLElement) {
        const href = link.getAttribute('href')
        if (href) {
          const sectionId = href.slice(1)
          if (sections.includes(sectionId)) {
            setActiveSection(sectionId)
          }
        }
      }
    }

    window.addEventListener('hashchange', handleHashChange)
    document.addEventListener('click', handleClick)

    return () => {
      observer.disconnect()
      window.removeEventListener('hashchange', handleHashChange)
      document.removeEventListener('click', handleClick)
    }
  }, [])

  return activeSection
}

export default useNavSpy