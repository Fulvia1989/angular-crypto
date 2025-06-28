import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: ['buffer', 'crypto'],
      globals: {
        Buffer: true,
        process: true,
      },
      protocolImports: true,
    }),
  ],
  optimizeDeps: {
    include: ['buffer','pbkdf2','crypto'], // forza l’inclusione nei deps precompilati
  },
});
