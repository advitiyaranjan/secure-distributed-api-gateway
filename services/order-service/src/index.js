import { gracefulShutdown } from '../../../shared/http.js';
import { start } from './server.js';

const { server, logger, close } = await start();
gracefulShutdown({ servers: [server], logger, cleanup: close });
