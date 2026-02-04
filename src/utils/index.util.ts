import { networkInterfaces } from 'os';
import { INetworkInfo } from 'src/interfaces/network-info.interface';

/**
 * Obtém informações sobre todas as interfaces de rede disponíveis
 */
export function getNetworkInterfaces(): INetworkInfo[] {
  const interfaces = networkInterfaces();
  const info: INetworkInfo[] = [];

  for (const [name, nets] of Object.entries(interfaces)) {
    if (!nets) continue;
    for (const net of nets) {
      if (net.family === 'IPv4') {
        info.push({
          address: net.address,
          internal: net.internal,
          interface: name,
        });
      }
    }
  }

  return info;
}
