import { prisma } from '../lib/db.js';
import crypto from 'crypto';

async function main() {
  const client = await prisma.authClient.findFirst({
    where: { clientId: 'furtail-web' },
    select: {
      clientId: true,
      clientSecretHash: true,
    }
  });

  const secretToTest = 'furtail-secret';
  const candidateHash = crypto.createHash('sha256').update(secretToTest).digest('hex');
  const storedHash = client?.clientSecretHash || '';
  
  console.log("Stored hash:", storedHash.slice(0, 16) + "...");
  console.log("SHA256('furtail-secret'):", candidateHash.slice(0, 16) + "...");
  
  const a = Buffer.from(candidateHash, 'utf8');
  const b = Buffer.from(storedHash, 'utf8');
  
  console.log("Length match:", a.length === b.length);
  if (a.length === b.length) {
    const match = crypto.timingSafeEqual(a, b);
    console.log("HASH MATCH:", match);
    console.log("LOGIN WILL:", match ? "SUCCEED" : "FAIL with INVALID_CLIENT 401");
  } else {
    console.log("HASH MATCH: false (different lengths)");
    console.log("LOGIN WILL: FAIL with INVALID_CLIENT 401");
  }
}

main().catch(err => {
  console.error("Error:", err);
}).finally(() => {
  prisma.$disconnect();
});
