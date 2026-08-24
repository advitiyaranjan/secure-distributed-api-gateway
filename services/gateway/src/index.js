import { gracefulShutdown } from '../../../shared/http.js';
import { start } from './server.js';

const { servers, logger, close } = await start();
gracefulShutdown({ servers, logger, cleanup: close });
