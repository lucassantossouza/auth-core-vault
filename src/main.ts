import { hostname } from 'os';
import { ConfigService } from '@nestjs/config';
import { INetworkInfo } from './interfaces/network-info.interface';
import { getNetworkInterfaces } from './utils/index.util';
import { app } from './app';

function formatUrl(schema: string, host: string, port: number): string {
  return `${schema}://${host}:${port}`;
}

async function bootstrap(): Promise<void> {
  const application = await app();
  const configService = application.get(ConfigService);
  const port = configService.get<number>('PORT', 3000);
  const environment = configService.get<string>('NODE_ENV', 'development');

  // Habilita graceful shutdown para que os hooks de lifecycle sejam executados
  // Isso permite que notificações de encerramento sejam enviadas corretamente
  application.enableShutdownHooks();

  await application.listen(port, '0.0.0.0');

  // Collect network information
  const networks = getNetworkInterfaces();
  const internalIps = networks.filter((net: INetworkInfo) => net.internal);
  const externalIps = networks.filter((net: INetworkInfo) => !net.internal);

  // ASCII Art Header
  console.log('\n');
  console.log(
    '\x1b[36m%s\x1b[0m',
    '╔═══════════════════════════════════════════════════════════╗',
  );
  console.log(
    '\x1b[36m%s\x1b[0m',
    '║                   SERVER STARTED                          ║',
  );
  console.log(
    '\x1b[36m%s\x1b[0m',
    '╚═══════════════════════════════════════════════════════════╝',
  );

  // Environment & Host Information
  console.log('\n\x1b[32m%s\x1b[0m', '📋 Environment Information:');
  console.log(`   Environment: \x1b[33m${environment.toUpperCase()}\x1b[0m`);
  console.log(`   Port:        \x1b[33m${port}\x1b[0m`);
  console.log(`   Hostname:    \x1b[33m${hostname()}\x1b[0m`);

  // Localhost Access
  console.log('\n\x1b[32m%s\x1b[0m', '🏠 Local Access:');
  console.log(`   → \x1b[36m${formatUrl('http', 'localhost', port)}\x1b[0m`);
  console.log(`   → \x1b[36m${formatUrl('http', '127.0.0.1', port)}\x1b[0m`);

  // Internal Network Access
  if (internalIps.length > 0) {
    console.log('\n\x1b[32m%s\x1b[0m', '🔒 Internal Network:');
    internalIps.forEach(({ address, interface: iface }) => {
      const url = formatUrl('http', address, port);
      console.log(`   → \x1b[36m${url}\x1b[0m \x1b[90m(${iface})\x1b[0m`);
    });
  }

  // External Network Access
  if (externalIps.length > 0) {
    console.log('\n\x1b[32m%s\x1b[0m', '🌐 External Network:');
    externalIps.forEach(({ address, interface: iface }) => {
      const url = formatUrl('http', address, port);
      console.log(`   → \x1b[36m${url}\x1b[0m \x1b[90m(${iface})\x1b[0m`);
    });
  } else {
    console.log(
      '\n\x1b[33m%s\x1b[0m',
      '⚠️  No external network interfaces found',
    );
  }

  // Footer
  console.log(
    '\n\x1b[36m%s\x1b[0m',
    '═══════════════════════════════════════════════════════════\n',
  );
}

void bootstrap();
