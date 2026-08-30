import { prisma } from '../lib/db.js';

async function main() {
  const sessions = await prisma.loginSession.findMany({
    orderBy: { lastActiveAt: 'desc' },
    include: { user: true }
  });
  console.log("ALL SESSIONS IN WPA AUTH:");
  for (const s of sessions) {
    console.log(`- SessionId: ${s.id}`);
    console.log(`  UserId: ${s.userId} (sub)`);
    console.log(`  Email: ${s.user.email}`);
    console.log(`  UserAgent: ${s.userAgent}`);
    console.log(`  IP: ${s.ipAddress}`);
    console.log(`  CreatedAt: ${s.createdAt}`);
    console.log(`  LastActiveAt: ${s.lastActiveAt}`);
    console.log(`  ExpiresAt: ${s.expiresAt}`);
    console.log(`  Revoked: ${!!s.revokedAt}`);
    console.log("------------------------");
  }
}

main().catch(console.error).finally(() => prisma.$disconnect());
