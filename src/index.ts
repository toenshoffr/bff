import { createApp } from './app.js';
import { config } from './config.js';
import { closeSessionBackend, connectSessionBackend } from './session/session-backend.js';

await connectSessionBackend();

const app = createApp();

const server = app.listen(config.port, () => {
  console.log(`BFF listening on port ${config.port}`);
  console.log(`  -> Angular origin:  ${config.frontendOrigin}`);
  console.log(`  -> Spring Boot API: ${config.api.baseUrl}`);
  console.log(`  -> Auth methods:    ${config.authMethods.join(', ')}`);
  console.log(`  -> Session store:   ${config.session.store}${config.session.encryptionEnabled ? ' (encrypted)' : ''}`);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    server.close(() => {
      void closeSessionBackend().finally(() => process.exit(0));
    });
  });
}
