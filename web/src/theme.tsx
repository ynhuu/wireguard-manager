import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

export type ThemeMode = 'system' | 'light' | 'dark'

const ThemeContext = createContext<{
  mode: ThemeMode
  cycleMode: () => void
}>({
  mode: 'system',
  cycleMode: () => {},
})

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    let saved = ''
    try {
      saved = localStorage.getItem('wg-theme') || ''
    } catch {
      /* storage can be unavailable in privacy-restricted browsers */
    }
    return saved === 'light' || saved === 'dark' ? saved : 'system'
  })

  useEffect(() => {
    document.documentElement.dataset.theme = mode
    try {
      if (mode === 'system') localStorage.removeItem('wg-theme')
      else localStorage.setItem('wg-theme', mode)
    } catch {
      /* theme still applies for the current session */
    }
  }, [mode])

  function cycleMode() {
    setModeState((current) => (current === 'system' ? 'light' : current === 'light' ? 'dark' : 'system'))
  }

  return <ThemeContext.Provider value={{ mode, cycleMode }}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  return useContext(ThemeContext)
}

export function themeLabel(mode: ThemeMode) {
  return mode === 'system' ? '跟随系统' : mode === 'light' ? '浅色模式' : '暗色模式'
}
