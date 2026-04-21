import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Whitelist your specific remote domain
    allowedHosts: ['app.weasts.net'],
    
    // Explicitly define the host binding here 
    // when working inside Docker.
    host: '0.0.0.0',
    port: 5173
  }
})