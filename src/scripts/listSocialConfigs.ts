import { prisma } from '../lib/db.js';

async function main() {
  const configs = await prisma.socialIdentityProviderConfig.findMany({
    select: {
      provider: true,
      status: true,
      showOnLogin: true,
      displayName: true,
    }
  });
  console.log("SOCIAL_PROVIDERS_CONFIGS:", JSON.stringify(configs, null, 2));
}

main().catch(err => {
  console.error("Error querying prisma:", err);
}).finally(() => {
  prisma.$disconnect();
});
