import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import path from 'path'

const certDir = path.resolve(__dirname, '../certs')

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 29993,
    https: {
      key: fs.readFileSync(path.join(certDir, 'xdr-key.pem')),
      cert: fs.readFileSync(path.join(certDir, 'xdr.pem')),
    },
    proxy: {
      '/api': {
        target: 'https://127.0.0.1:29992',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  preview: {
    host: '127.0.0.1',
    port: 29993,
    https: {
      key: fs.readFileSync(path.join(certDir, 'xdr-key.pem')),
      cert: fs.readFileSync(path.join(certDir, 'xdr.pem')),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
