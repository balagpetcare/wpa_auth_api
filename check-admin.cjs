const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
async function main() {
  const user = await prisma.user.findFirst({
    where: { email: 'admin@wpa.invalid' },
    include: {
      adminRecord: true,
      userRoles: { include: { role: true } },
      applications: { include: { application: true } },
      credential: { select: { id: true, authMode: true } }
    }
  });
  console.log(JSON.stringify(user, null, 2));
}
main().catch(console.error).finally(() => prisma.$disconnect());
