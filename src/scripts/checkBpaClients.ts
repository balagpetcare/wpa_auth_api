import { prisma } from '../lib/db.js';

async function main() {
  const clients = await prisma.authClient.findMany({
    where: {
      OR: [
        { clientId: { contains: 'bpa' } },
        { slug: { contains: 'bpa' } }
      ]
    }
  });
  console.log("BPA CLIENTS:", JSON.stringify(clients, null, 2));
}

main().catch(console.error).finally(() => prisma.$disconnect());
