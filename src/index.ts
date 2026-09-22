import { createApp } from './app.js';
import { config } from './config.js';

const app = createApp();

app.listen(config.port, () => {
  console.log(`BFF listening on port ${config.port}`);
  console.log(`  -> Angular origin:  ${config.frontendOrigin}`);
  console.log(`  -> Spring Boot API: ${config.api.baseUrl}`);
  console.log(`  -> Auth methods:    ${config.authMethods.join(', ')}`);
});
