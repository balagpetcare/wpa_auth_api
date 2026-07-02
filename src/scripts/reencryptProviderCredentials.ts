import { reencryptProviderCredentials } from '../services/keyRotation.service.js';
import { prisma } from '../lib/db.js';

function parseArgs(argv: string[]) {
  return {
    dryRun: argv.includes('--dry-run'),
    batchSize: (() => {
      const match = argv.find((arg) => arg.startsWith('--batch-size='));
      if (!match) return undefined;
      const value = Number(match.split('=')[1]);
      return Number.isFinite(value) ? value : undefined;
    })(),
  };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const summary = await reencryptProviderCredentials(opts);
  console.log(JSON.stringify({ event: 'provider_credential_reencryption', ...summary }, null, 2));
}

main()
  .catch((err) => {
    console.error('Provider credential re-encryption failed:', err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
