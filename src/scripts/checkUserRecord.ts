import { prisma } from '../lib/db.js';

async function main() {
  const phones = ['01701022200', '+8801701022200', '8801701022200'];
  
  for (const phone of phones) {
    const user = await prisma.user.findFirst({
      where: { phone },
      select: {
        id: true,
        phone: true,
        email: true,
        status: true,
        phoneVerifiedAt: true,
        emailVerifiedAt: true,
      }
    });
    
    if (user) {
      console.log(`FOUND USER FOR PHONE: ${phone}`);
      console.log(`User ID: ${user.id}`);
      console.log(`Stored phone: ${user.phone}`);
      // Partially mask email
      const maskedEmail = user.email ? user.email.replace(/(?<=.).(?=.*@)/g, '*') : 'null';
      console.log(`Stored email: ${maskedEmail}`);
      console.log(`Status: ${user.status}`);
      console.log(`Phone verified: ${!!user.phoneVerifiedAt}`);
      console.log(`Email verified: ${!!user.emailVerifiedAt}`);
      console.log('---');
    }
  }
}

main().catch(err => {
  console.error("Error:", err);
}).finally(() => {
  prisma.$disconnect();
});
