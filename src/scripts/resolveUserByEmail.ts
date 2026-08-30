import { prisma } from '../lib/db.js';

async function main() {
  const email = process.argv[2]?.trim().toLowerCase();
  if (!email) {
    throw new Error('Usage: tsx src/scripts/resolveUserByEmail.ts <email>');
  }

  const user = await prisma.user.findFirst({
    where: { email },
    select: {
      id: true,
      email: true,
      displayName: true,
      username: true,
      status: true,
      emailVerifiedAt: true,
      phoneVerifiedAt: true,
    },
  });

  console.log(JSON.stringify(user, null, 2));
}

main()
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
