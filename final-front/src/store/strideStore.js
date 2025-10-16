import { create } from 'zustand'

export const useStrideStore = create((set) => ({
  threats: [],
  isAnalyzing: false,
  setThreats: (threats) => set({ threats }),
  setIsAnalyzing: (isAnalyzing) => set({ isAnalyzing }),
  clearThreats: () => set({ threats: [] })
}))