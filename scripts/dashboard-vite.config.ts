// mockserver-ui's own vite.config.ts plus a plugin that records the modules each output chunk is built from, in the
// main build and in the web-worker builds, as build-modules.json. scripts/dashboard-notices.py reads it to list the
// packages whose code ends up in the bundle. The plugin only reads the bundle, so the output is unchanged.
// scripts/build-dashboard.sh copies this file next to vite.config.ts in its working copy of mockserver-ui.
import { writeFileSync } from 'node:fs';
import type { Plugin } from 'vite';
import base from './vite.config';

const modules = new Set<string>();

function recordModules(): Plugin {
  return {
    name: 'mock-server-module-list',
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        if (output.type === 'chunk') {
          output.moduleIds.forEach((id) => modules.add(id));
        }
      }
    },
    closeBundle() {
      writeFileSync('build-modules.json', JSON.stringify([...modules].sort(), null, 1) + '\n');
    },
  };
}

export default {
  ...base,
  plugins: [...(base.plugins ?? []), recordModules()],
  worker: { ...base.worker, plugins: () => [recordModules()] },
};
