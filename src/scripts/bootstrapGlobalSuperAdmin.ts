import dotenv from 'dotenv';
dotenv.config();

import readline from 'readline';
import bcrypt from 'bcrypt';
import { prisma } from '../lib/db.js';
import { writeAuditLog } from '../lib/audit.js';
import { BCRYPT_ROUNDS } from '../modules/auth/auth.service.js';
import { ensureGlobalSuperAdminRbac, GLOBAL_SUPER_ADMIN_ROLE } from './ensureGlobalSuperAdminRbac.js';

// One-time / idempotent bootstrap for the unified Global Super Admin
// identity. Interactive only — never accepts email/password via argv or
// env, so credentials never land in shell history, process listings, or
// logs. Never prints the password or its hash at any point.
//
// Usage: npm run bootstrap:global-super-admin
//        (add --confirm-existing-user to knowingly convert a pre-existing,
//        non-super-admin account into the Global Super Admin — otherwise
//        an email collision with an unrelated account aborts loudly.)

function prompt(query: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function promptHidden(query: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      reject(new Error('This script must be run interactively at a real terminal (stdin is not a TTY).'));
      return;
    }
    process.stdout.write(query);

    const ENTER_CHARS = ['\n', '\r'];
    const EOF_CHAR = String.fromCharCode(4); // Ctrl-D
    const SIGINT_CHAR = String.fromCharCode(3); // Ctrl-C
    const BACKSPACE_CHARS = [String.fromCharCode(127), '\b']; // DEL and BS

    let value = '';
    const onData = (charBuf: Buffer) => {
      const char = charBuf.toString('utf8');
      if (ENTER_CHARS.includes(char) || char === EOF_CHAR) {
        stdin.removeListener('data', onData);
        stdin.setRawMode(false);
        stdin.pause();
        process.stdout.write('\n');
        resolve(value);
        return;
      }
      if (char === SIGINT_CHAR) {
        process.stdout.write('\n');
        process.exit(130);
      }
      if (BACKSPACE_CHARS.includes(char)) {
        value = value.slice(0, -1);
        return;
      }
      value += char;
    };

    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    stdin.on('data', onData);
  });
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function passwordStrengthIssues(password: string, email: string): string[] {
  const issues: string[] = [];
  if (password.length < 12) issues.push('must be at least 12 characters');
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 3) issues.push('must contain at least 3 of: lowercase, uppercase, digit, symbol');
  const localPart = email.split('@')[0]?.toLowerCase();
  if (localPart && password.toLowerCase().includes(localPart)) {
    issues.push('must not contain your email address');
  }
  return issues;
}

async function main() {
  const confirmExistingUser = process.argv.includes('--confirm-existing-user');

  console.log('=== Global Super Admin bootstrap (WPA Central Auth) ===');
  console.log('This grants unified GLOBAL_SUPER_ADMIN access to BPA, WPA, WPA Gateway, and Furtail.\n');

  const emailRaw = await prompt('Operator email: ');
  if (!isValidEmail(emailRaw)) {
    console.error('Invalid email address.');
    process.exitCode = 1;
    return;
  }
  const email = emailRaw.toLowerCase();

  const password = await promptHidden('Password (hidden): ');
  const confirmPassword = await promptHidden('Confirm password (hidden): ');
  if (password !== confirmPassword) {
    console.error('Passwords do not match.');
    process.exitCode = 1;
    return;
  }
  const issues = passwordStrengthIssues(password, email);
  if (issues.length > 0) {
    console.error('Password does not meet the minimum requirements:');
    for (const issue of issues) console.error(`  - ${issue}`);
    process.exitCode = 1;
    return;
  }

  const existing = await prisma.user.findFirst({
    where: { email: { equals: email, mode: 'insensitive' } },
    include: { roles: { include: { role: true } } },
  });

  const hasGlobalSuperAdmin = existing?.roles.some((r) => r.role.name === GLOBAL_SUPER_ADMIN_ROLE) ?? false;

  if (existing && !hasGlobalSuperAdmin && !confirmExistingUser) {
    console.error('\nConflict: an account with this email already exists and does NOT currently hold GLOBAL_SUPER_ADMIN.');
    console.error(`  userId: ${existing.id}`);
    console.error(`  status: ${existing.status}`);
    console.error(`  existing roles: ${existing.roles.map((r) => r.role.name).join(', ') || '(none)'}`);
    console.error(`  created: ${existing.createdAt.toISOString()}`);
    console.error('\nRefusing to silently modify an unrelated account.');
    console.error('If you intend to promote this exact account to Global Super Admin, re-run with --confirm-existing-user.');
    process.exitCode = 1;
    return;
  }

  let shouldSetPassword = true;
  if (existing && hasGlobalSuperAdmin) {
    const rotate = (await prompt('This account is already GLOBAL_SUPER_ADMIN. Rotate its password now? (y/N): '))
      .trim()
      .toLowerCase();
    shouldSetPassword = rotate === 'y' || rotate === 'yes';
    if (!shouldSetPassword) {
      console.log('No changes made to password (rotation declined). Role/permission assignment will still be re-verified idempotently.');
    }
  }

  const passwordHash = shouldSetPassword ? await bcrypt.hash(password, BCRYPT_ROUNDS) : undefined;

  const { roleId, permissionNames } = await ensureGlobalSuperAdminRbac();
  const legacySuperAdminRole = await prisma.role.findFirst({ where: { name: { in: ['super_admin', 'SUPER_ADMIN'] } } });

  const user = existing
    ? await prisma.user.update({
        where: { id: existing.id },
        data: {
          ...(passwordHash ? { passwordHash, lastPasswordChangedAt: new Date() } : {}),
          status: 'ACTIVE',
          emailVerifiedAt: existing.emailVerifiedAt ?? new Date(),
        },
      })
    : await prisma.user.create({
        data: {
          email,
          passwordHash,
          status: 'ACTIVE',
          emailVerifiedAt: new Date(),
        },
      });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId } },
    update: {},
    create: { userId: user.id, roleId },
  });

  const assignedRoleNames = [GLOBAL_SUPER_ADMIN_ROLE];
  if (legacySuperAdminRole) {
    await prisma.userRole.upsert({
      where: { userId_roleId: { userId: user.id, roleId: legacySuperAdminRole.id } },
      update: {},
      create: { userId: user.id, roleId: legacySuperAdminRole.id },
    });
    assignedRoleNames.push(legacySuperAdminRole.name);
  }

  await writeAuditLog({
    userId: user.id,
    action: 'ROLE_ASSIGNED',
    resource: 'global_super_admin_bootstrap',
    resourceId: user.id,
    metadata: {
      event: 'global_super_admin_bootstrap',
      roles: assignedRoleNames,
      permissions: permissionNames,
      wasExistingAccount: Boolean(existing),
      passwordChanged: Boolean(passwordHash),
    },
  });

  console.log('\n=== Done ===');
  console.log(`userId: ${user.id}`);
  console.log(`email: ${user.email}`);
  console.log(`roles assigned: ${assignedRoleNames.join(', ')}`);
  console.log(`service permissions: ${permissionNames.join(', ')}`);
  console.log('Password/hash were never printed or logged.');
}

main()
  .catch((err) => {
    console.error('Bootstrap failed:', err instanceof Error ? err.message : err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
