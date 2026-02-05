import { HttpModuleOptions } from '@nestjs/axios';
import { Agent, AgentOptions } from 'http';
import { Agent as HttpsAgent, AgentOptions as HttpsAgentOptions } from 'https';

const agentOptions: AgentOptions = {
  keepAlive: true,
  keepAliveMsecs: 1000,
  maxSockets: 50,
  maxFreeSockets: 10,
};

const httpsAgentOptions: HttpsAgentOptions = {
  ...agentOptions,
  rejectUnauthorized: true,
};

/** Opções HTTP padrão para o HttpModule (forRoot, forFeature). */
export const defaultHttpOptions: HttpModuleOptions = {
  timeout: 3000,
  maxRedirects: 3,
  httpAgent: new Agent({ ...agentOptions }),
  httpsAgent: new HttpsAgent(httpsAgentOptions),
};
