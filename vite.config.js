import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import commonjs from '@rollup/plugin-commonjs';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    commonjs()
  ],
  optimizeDeps: {
    // QUITA 'react-simple-code-editor' de 'exclude'
    exclude: [], // <-- DEBE ESTAR VACÍO O ELIMINA LA LÍNEA SI YA LO ESTÁ

    // AÑADE ESTA LÍNEA para incluir explícitamente 'react-simple-code-editor'
    include: ['react-simple-code-editor'], // <-- NUEVA LÍNEA CLAVE
  },
});