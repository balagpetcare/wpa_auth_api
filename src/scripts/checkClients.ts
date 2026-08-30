import { prisma } from '../lib/db.js';

async function main() {
  const clients = await prisma.authClient.findMany();
  console.log(JSON.stringify(clients, null, 2));
}

main().finally(() => prisma.$disconnect());
