import { PrismaClient, AuthClientType, AuthClientStatus, UserStatus } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import 'dotenv/config';

const adapter = new PrismaPg({ connectionString: process.env['DATABASE_URL']! });
const prisma = new PrismaClient({ adapter });

const permissionsList = [
  { name: 'users:read', description: 'Read users', resource: 'users', action: 'read' },
  { name: 'users:write', description: 'Write users', resource: 'users', action: 'write' },
  { name: 'users:delete', description: 'Delete users', resource: 'users', action: 'delete' },
  { name: 'end_users.read', description: 'Read end users', resource: 'end_users', action: 'read' },
  { name: 'end_users.view_detail', description: 'View end user details', resource: 'end_users', action: 'view_detail' },
  { name: 'end_users.update_status', description: 'Suspend, activate, block end users', resource: 'end_users', action: 'update_status' },
  { name: 'end_users.force_logout', description: 'Force logout end user sessions', resource: 'end_users', action: 'force_logout' },
  { name: 'end_users.send_verification', description: 'Send end user verification messages', resource: 'end_users', action: 'send_verification' },
  { name: 'end_users.export', description: 'Export filtered end users', resource: 'end_users', action: 'export' },
  { name: 'end_users.security_view', description: 'View end user security data', resource: 'end_users', action: 'security_view' },
  { name: 'clients:read', description: 'Read clients', resource: 'clients', action: 'read' },
  { name: 'clients:write', description: 'Write clients', resource: 'clients', action: 'write' },
  { name: 'roles:read', description: 'Read roles', resource: 'roles', action: 'read' },
  { name: 'roles:write', description: 'Write roles', resource: 'roles', action: 'write' },
  // Phase 2 role-permission management API (see docs/wpa-central-auth-api-complete-audit.md).
  // Kept in the same `resource:action` naming convention as the existing roles:read/roles:write
  // above (rather than the newer `resource.action` dot convention used by communication/email
  // modules) for consistency with those two pre-existing role permissions.
  { name: 'roles:delete', description: 'Delete roles', resource: 'roles', action: 'delete' },
  { name: 'roles:manage', description: 'Create/update roles and manage role-permission assignments', resource: 'roles', action: 'manage' },
  { name: 'permissions:read', description: 'Read the permission catalog', resource: 'permissions', action: 'read' },
  // Phase 1 stabilization fix (docs/central-auth-api-admin-scalability-audit.md):
  // admin.routes.ts already referenced 'users:manage', 'admin:manage', and
  // 'admin:read' via requirePermission() on many routes (user CRUD, admin-team
  // management, invitations), but none of the three were ever seeded as real
  // Permission rows — meaning those checks could only ever be satisfied by
  // super_admin's automatic bypass. Seeding them here makes the checks
  // meaningful and grantable to custom roles without changing any existing
  // role's effective access (they are intentionally NOT added to ADMIN's
  // default permission set below, same as roles:manage).
  { name: 'users:manage', description: 'Update, suspend, delete users and manage their sessions/roles', resource: 'users', action: 'manage' },
  { name: 'admin:read', description: 'Read admin-team accounts and invitations', resource: 'admin', action: 'read' },
  { name: 'admin:manage', description: 'Manage admin-team accounts, promotions, and invitations', resource: 'admin', action: 'manage' },
  { name: 'communication.providers.read', description: 'Read communication providers', resource: 'communication.providers', action: 'read' },
  { name: 'communication.providers.create', description: 'Create communication providers', resource: 'communication.providers', action: 'create' },
  { name: 'communication.providers.update', description: 'Update communication providers', resource: 'communication.providers', action: 'update' },
  { name: 'communication.providers.delete', description: 'Delete communication providers', resource: 'communication.providers', action: 'delete' },
  { name: 'communication.credentials.manage', description: 'Manage communication provider credentials', resource: 'communication.credentials', action: 'manage' },
  { name: 'communication.providers.test', description: 'Test communication providers', resource: 'communication.providers', action: 'test' },
  { name: 'communication.routing.read', description: 'Read communication routing rules', resource: 'communication.routing', action: 'read' },
  { name: 'communication.routing.manage', description: 'Manage communication routing rules', resource: 'communication.routing', action: 'manage' },
  { name: 'communication.templates.read', description: 'Read OTP communication templates', resource: 'communication.templates', action: 'read' },
  { name: 'communication.templates.manage', description: 'Manage OTP communication templates', resource: 'communication.templates', action: 'manage' },
  { name: 'communication.logs.read', description: 'Read communication delivery and provider audit logs', resource: 'communication.logs', action: 'read' },
  { name: 'communication.logs.manage', description: 'Retry, cancel, and manually resend communication deliveries', resource: 'communication.logs', action: 'manage' },
  { name: 'communication.health.read', description: 'Read communication provider health', resource: 'communication.health', action: 'read' },
  { name: 'email_branding.read', description: 'Read email branding settings', resource: 'email_branding', action: 'read' },
  { name: 'email_branding.update', description: 'Update email branding settings', resource: 'email_branding', action: 'update' },
  { name: 'email_template.read', description: 'Read email templates', resource: 'email_template', action: 'read' },
  { name: 'email_template.update', description: 'Update email templates', resource: 'email_template', action: 'update' },
  { name: 'email_template.preview', description: 'Preview email templates', resource: 'email_template', action: 'preview' },
  { name: 'email_template.send_test', description: 'Send test emails', resource: 'email_template', action: 'send_test' },
  { name: 'email_template.reset', description: 'Reset email templates to default', resource: 'email_template', action: 'reset' },
  { name: 'email_logs.read', description: 'Read email send logs', resource: 'email_logs', action: 'read' },
];

const rolesList = [
  { name: 'SUPER_ADMIN', description: 'Full unrestricted access to all resources' },
  { name: 'ADMIN', description: 'Administrative access with limited destructive capabilities' },
  { name: 'SUPPORT', description: 'Support access to view user data' },
  { name: 'APP_MANAGER', description: 'Manage applications and clients' },
  { name: 'SECURITY_AUDITOR', description: 'Read-only access to audit logs and security events' },
  { name: 'USER', description: 'Standard authenticated user' },
];

const clientsList = [
  { name: 'World Pet Association', slug: 'world-pet-association', type: AuthClientType.FIRST_PARTY_APP },
  { name: 'Furtail', slug: 'furtail', type: AuthClientType.FIRST_PARTY_APP },
  { name: 'Fortail Lab', slug: 'fortail-lab', type: AuthClientType.FIRST_PARTY_APP },
  { name: 'Bangladesh Pet Association', slug: 'bangladesh-pet-association', type: AuthClientType.FIRST_PARTY_APP },
  { name: 'WPA Payment Gateway', slug: 'wpa-payment-gateway', type: AuthClientType.SERVICE },
  { name: 'Pet Smart Solution', slug: 'pet-smart-solution', type: AuthClientType.THIRD_PARTY_APP },
];

async function main() {
  console.log('Starting seed...');

  // 1. Permissions
  for (const p of permissionsList) {
    await prisma.permission.upsert({
      where: { name: p.name },
      update: { description: p.description, resource: p.resource, action: p.action },
      create: p,
    });
  }
  console.log('Permissions seeded.');

  // 2. Roles
  for (const r of rolesList) {
    await prisma.role.upsert({
      where: { name: r.name },
      update: { description: r.description },
      create: r,
    });
  }
  console.log('Roles seeded.');

  // 2b. Map all permissions to SUPER_ADMIN
  const superAdminRole = await prisma.role.findUnique({ where: { name: 'SUPER_ADMIN' } });
  if (superAdminRole) {
    const allPerms = await prisma.permission.findMany();
    for (const p of allPerms) {
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: superAdminRole.id, permissionId: p.id } },
        update: {},
        create: { roleId: superAdminRole.id, permissionId: p.id }
      });
    }
    console.log('Mapped all permissions to SUPER_ADMIN.');
  }

  // 2c. Phase 2: safe default read-only permissions for ADMIN (see
  // docs/wpa-central-auth-api-complete-audit.md, "Phase 2 Role-Permission API Update").
  // Intentionally read-only — ADMIN can view roles/permissions in the Larkon UI but
  // cannot create/update/delete roles or reassign permissions unless a super_admin
  // explicitly grants `roles:manage`/`roles:write`/`roles:delete` via the new
  // POST /admin/roles/:id/permissions API. SUPPORT and USER are intentionally left
  // unchanged (no roles/permissions access) to avoid over-permissioning them.
  const adminDefaultPermissionNames = ['roles:read', 'permissions:read'];
  const adminRoleForDefaults = await prisma.role.findUnique({ where: { name: 'ADMIN' } });
  if (adminRoleForDefaults) {
    const defaultPerms = await prisma.permission.findMany({ where: { name: { in: adminDefaultPermissionNames } } });
    for (const p of defaultPerms) {
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: adminRoleForDefaults.id, permissionId: p.id } },
        update: {},
        create: { roleId: adminRoleForDefaults.id, permissionId: p.id },
      });
    }
    console.log('Mapped safe default read-only permissions (roles:read, permissions:read) to ADMIN.');
  }

  // 3. Clients
  for (const c of clientsList) {
    const existing = await prisma.authClient.findUnique({ where: { slug: c.slug } });
    if (!existing) {
      const generatedSecret = crypto.randomBytes(32).toString('base64url');
      const hash = crypto.createHash('sha256').update(generatedSecret).digest('hex');
      
      const newClient = await prisma.authClient.create({
        data: {
          name: c.name,
          slug: c.slug,
          type: c.type,
          clientId: `${c.slug.replace(/-/g, '_')}_client_id`,
          clientSecretHash: hash,
          status: AuthClientStatus.ACTIVE,
          allowedOrigins: process.env.ALLOWED_PUBLIC_ORIGINS ? process.env.ALLOWED_PUBLIC_ORIGINS.split(',').map(s=>s.trim()) : ['*'],
          redirectUris: process.env.ALLOWED_PUBLIC_ORIGINS ? process.env.ALLOWED_PUBLIC_ORIGINS.split(',').map(s=>s.trim() + '/api/auth/callback') : ['http://localhost:3000/api/auth/callback'],
        },
      });
      console.log(`\n======================================================`);
      console.log(`[ACTION REQUIRED] Created new client: ${newClient.name}`);
      console.log(`Client ID: ${newClient.clientId}`);
      console.log(`Client Secret: ${generatedSecret}`);
      console.log(`WARNING: Please save this secret now! It will never be shown again.`);
      console.log(`======================================================\n`);
    } else {
      let updatedHash: string | undefined = undefined;

      if (!existing.clientSecretHash && c.type === AuthClientType.SERVICE) {
        // Dev fallback secret from environment or standard secure dev string
        const devSecret = process.env.DEV_PAYMENT_GATEWAY_SECRET || 'wpa_payment_gateway_dev_secret_2026';
        updatedHash = crypto.createHash('sha256').update(devSecret).digest('hex');

        console.log(`\n======================================================`);
        console.log(`[DEV PROVISIONING] Seeded missing client secret for: ${c.name}`);
        console.log(`Client ID: ${existing.clientId}`);
        console.log(`Dev Client Secret: ${devSecret}`);
        console.log(`WARNING: This is a fallback dev-only secret. In production, rotate this secret!`);
        console.log(`======================================================\n`);
      }

      await prisma.authClient.update({
        where: { id: existing.id },
        data: { 
          name: c.name, 
          type: c.type,
          ...(updatedHash ? { clientSecretHash: updatedHash } : {})
        }
      });
    }
  }
  console.log('Clients seeded.');

  // 4. Initial Super Admin
  const adminEmail = process.env.SEED_ADMIN_EMAIL;
  const adminUsername = process.env.SEED_ADMIN_USERNAME;
  const adminPassword = process.env.SEED_ADMIN_PASSWORD;

  if (!adminEmail || !adminUsername || !adminPassword) {
    console.warn('\n[WARNING] Missing SEED_ADMIN_EMAIL, SEED_ADMIN_USERNAME, or SEED_ADMIN_PASSWORD in environment.');
    console.warn('[WARNING] Initial super admin will NOT be created.\n');
  } else {
    const existingAdmin = await prisma.user.findUnique({ where: { email: adminEmail } });

    if (!superAdminRole) throw new Error('SUPER_ADMIN role not found');

    if (existingAdmin) {
      console.log(`Admin user with email ${adminEmail} already exists.`);
      
      const updateData: any = { username: adminUsername };

      if (process.env.FORCE_ADMIN_PASSWORD_RESET === 'true') {
        console.log('FORCE_ADMIN_PASSWORD_RESET=true is set, resetting admin password...');
        updateData.passwordHash = await bcrypt.hash(adminPassword, 10);
      } else {
        console.log('FORCE_ADMIN_PASSWORD_RESET is not true, skipping password overwrite.');
      }

      await prisma.user.update({
        where: { email: adminEmail },
        data: updateData
      });
      
      // Ensure role is attached
      await prisma.userRole.upsert({
        where: { userId_roleId: { userId: existingAdmin.id, roleId: superAdminRole.id } },
        update: {},
        create: { userId: existingAdmin.id, roleId: superAdminRole.id }
      });

    } else {
      console.log(`Creating initial admin user: ${adminEmail}`);
      const passwordHash = await bcrypt.hash(adminPassword, 10);

      await prisma.user.create({
        data: {
          email: adminEmail,
          username: adminUsername,
          passwordHash,
          status: UserStatus.ACTIVE,
          emailVerifiedAt: new Date(),
          roles: {
            create: {
              roleId: superAdminRole.id
            }
          }
        }
      });
    }
  }

  const seededAdmin = adminEmail ? await prisma.user.findUnique({ where: { email: adminEmail } }) : null;
  const runDemoSeeds = process.env.SEED_DEMO_NOTIFICATIONS === 'true' || process.argv.includes('--demo-notifications');
  if (seededAdmin && runDemoSeeds) {
    const existingWelcomeCount = await prisma.adminNotification.count({
      where: {
        userId: seededAdmin.id,
        type: { in: ['WELCOME', 'PROFILE_READY', 'SECURITY_MONITORING'] },
      },
    });

    if (existingWelcomeCount === 0) {
      await prisma.adminNotification.createMany({
        data: [
          {
            userId: seededAdmin.id,
            type: 'WELCOME',
            title: 'Welcome to WPA Central Auth',
            message: 'Your enterprise admin workspace for World Pet Association is ready.',
            severity: 'SUCCESS',
            category: 'SYSTEM',
            actionUrl: '/account',
          },
          {
            userId: seededAdmin.id,
            type: 'PROFILE_READY',
            title: 'Profile settings are ready',
            message: 'Review your account profile, security preferences, and avatar settings.',
            severity: 'INFO',
            category: 'SYSTEM',
            actionUrl: '/account',
          },
          {
            userId: seededAdmin.id,
            type: 'SECURITY_MONITORING',
            title: 'Security monitoring enabled',
            message: 'Audit logs, sessions, and security events are being tracked for your admin account.',
            severity: 'INFO',
            category: 'SECURITY',
            actionUrl: '/security-events',
          },
        ],
      });
      console.log('Seed admin notifications created.');
    }
  }

  const defaultTemplates = [
    {
      channel: 'SMS',
      purpose: 'LOGIN',
      language: 'EN',
      subject: null,
      body: 'Your WPA verification code is {{otp}}. It will expire in {{minutes}} minutes.',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
    {
      channel: 'SMS',
      purpose: 'LOGIN',
      language: 'BN',
      subject: null,
      body: 'আপনার WPA যাচাইকরণ কোড {{otp}}। এটি {{minutes}} মিনিটের মধ্যে মেয়াদোত্তীর্ণ হবে।',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
    {
      channel: 'SMS',
      purpose: 'PASSWORD_RESET',
      language: 'EN',
      subject: null,
      body: 'Your WPA password reset code is {{otp}}. It will expire in {{minutes}} minutes.',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
    {
      channel: 'EMAIL',
      purpose: 'LOGIN',
      language: 'EN',
      subject: 'Your WPA verification code',
      body: 'Your WPA verification code is {{otp}}.\n\nThis code expires in {{minutes}} minutes.\n\nIf you did not request this code, contact {{supportEmail}} immediately.',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
    {
      channel: 'EMAIL',
      purpose: 'PASSWORD_RESET',
      language: 'EN',
      subject: 'Your WPA verification code',
      body: 'Your WPA password reset code is {{otp}}.\n\nThis code expires in {{minutes}} minutes.\n\nIf you did not request this code, contact {{supportEmail}} immediately.',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
    {
      channel: 'EMAIL',
      purpose: 'GENERAL',
      language: 'EN',
      subject: 'Your WPA verification code',
      body: 'Your WPA verification code is {{otp}}.\n\nThis code expires in {{minutes}} minutes.\n\nIf you did not request this code, contact {{supportEmail}} immediately.',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
    {
      channel: 'EMAIL',
      purpose: 'ADMIN_INVITE',
      language: 'EN',
      subject: 'Your WPA verification code',
      body: 'Your WPA verification code is {{otp}}.\n\nThis code expires in {{minutes}} minutes.\n\nIf you did not request this code, contact {{supportEmail}} immediately.',
      variables: ['otp', 'minutes', 'appName', 'purpose', 'supportEmail'],
      isDefault: true,
      isActive: true,
    },
  ] as const;

  for (const template of defaultTemplates) {
    await prisma.otpTemplate.upsert({
      where: {
        channel_purpose_language: {
          channel: template.channel,
          purpose: template.purpose,
          language: template.language,
        }
      },
      update: {
        subject: template.subject,
        body: template.body,
        variables: template.variables as any,
        isDefault: template.isDefault,
        isActive: template.isActive,
      },
      create: {
        channel: template.channel as any,
        purpose: template.purpose as any,
        language: template.language as any,
        subject: template.subject,
        body: template.body,
        variables: template.variables as any,
        isDefault: template.isDefault,
        isActive: template.isActive,
      }
    });
  }
  console.log('OTP communication templates seeded.');

  // 5. Test non-super-admin user for local development
  // Phase 1 audit fix (docs/wpa-central-auth-api-complete-audit.md): this hardcoded
  // test account must NEVER be created in production. Guarded explicitly below —
  // do not remove this guard.
  if (process.env.NODE_ENV === 'production') {
    console.log('NODE_ENV=production — skipping hardcoded test user creation.');
  } else {
    const testEmail = 'testuser@wpa.com';
    const testUsername = 'testuser';
    const testPassword = 'Password123!';
    const userRole = await prisma.role.findUnique({ where: { name: 'USER' } });

    if (userRole) {
      const existingTestUser = await prisma.user.findUnique({ where: { email: testEmail } });
      if (!existingTestUser) {
        console.log(`Creating test user: ${testEmail}`);
        const testPasswordHash = await bcrypt.hash(testPassword, 10);
        await prisma.user.create({
          data: {
            email: testEmail,
            username: testUsername,
            displayName: 'Test User',
            passwordHash: testPasswordHash,
            status: UserStatus.ACTIVE,
            emailVerifiedAt: new Date(),
            roles: {
              create: {
                roleId: userRole.id
              }
            }
          }
        });
        console.log('Test user created successfully.');
      } else {
        console.log('Test user already exists.');
      }
    }
  }

  // 6. Email Branding Settings
  const forceReseed = process.env.FORCE_RESEED === 'true';

  // Check if branding has been edited by admin
  const existingBranding = await prisma.emailBrandingSetting.findFirst({
    where: { isActive: true }
  });

  if (!existingBranding || forceReseed) {
    const seededAdminId = seededAdmin?.id;

    await prisma.emailBrandingSetting.upsert({
      where: { id: existingBranding?.id || 'wpa-default-branding' },
      update: forceReseed ? {
        brandName: 'World Pet Association',
        logoUrl: 'https://cdn.worldpetassociation.org/logo.png',
        logoAltText: 'World Pet Association Logo',
        primaryColor: '#0f3a7d',
        textColor: '#333333',
        headerBackgroundColor: '#0f3a7d',
        footerBackgroundColor: '#f5f5f5',
        supportEmail: 'support@worldpetassociation.org',
        supportPhone: '+1-800-555-0000',
        websiteUrl: 'https://worldpetassociation.org',
        privacyUrl: 'https://worldpetassociation.org/privacy',
        termsUrl: 'https://worldpetassociation.org/terms',
        helpUrl: 'https://help.worldpetassociation.org',
        contactUrl: 'https://worldpetassociation.org/contact',
        facebookUrl: 'https://facebook.com/worldpetassociation',
        instagramUrl: 'https://instagram.com/worldpetassociation',
        linkedinUrl: 'https://linkedin.com/company/world-pet-association',
        twitterUrl: 'https://twitter.com/wpa_official',
        youtubeUrl: 'https://youtube.com/@worldpetassociation',
        tiktokUrl: 'https://tiktok.com/@wpa_official',
        footerText: '© 2024 World Pet Association. All rights reserved.',
        address: '123 Pet Street, Animal City, AC 12345',
        legalDisclaimer: 'This is an automated message. Please do not reply directly to this email.',
        isActive: true,
        updatedByAdminId: seededAdminId
      } : {},
      create: {
        id: 'wpa-default-branding',
        brandName: 'World Pet Association',
        logoUrl: 'https://cdn.worldpetassociation.org/logo.png',
        logoAltText: 'World Pet Association Logo',
        primaryColor: '#0f3a7d',
        textColor: '#333333',
        headerBackgroundColor: '#0f3a7d',
        footerBackgroundColor: '#f5f5f5',
        supportEmail: 'support@worldpetassociation.org',
        supportPhone: '+1-800-555-0000',
        websiteUrl: 'https://worldpetassociation.org',
        privacyUrl: 'https://worldpetassociation.org/privacy',
        termsUrl: 'https://worldpetassociation.org/terms',
        helpUrl: 'https://help.worldpetassociation.org',
        contactUrl: 'https://worldpetassociation.org/contact',
        facebookUrl: 'https://facebook.com/worldpetassociation',
        instagramUrl: 'https://instagram.com/worldpetassociation',
        linkedinUrl: 'https://linkedin.com/company/world-pet-association',
        twitterUrl: 'https://twitter.com/wpa_official',
        youtubeUrl: 'https://youtube.com/@worldpetassociation',
        tiktokUrl: 'https://tiktok.com/@wpa_official',
        footerText: '© 2024 World Pet Association. All rights reserved.',
        address: '123 Pet Street, Animal City, AC 12345',
        legalDisclaimer: 'This is an automated message. Please do not reply directly to this email.',
        isActive: true,
        updatedByAdminId: seededAdminId
      }
    });
    console.log('Email branding settings seeded.');
  } else {
    console.log('Email branding already configured by admin. Use FORCE_RESEED=true to override.');
  }

  // 7. Email Templates for Authentication & Security
  const emailTemplates = [
    {
      key: 'otp_login',
      name: 'OTP Login Code',
      subject: 'Your WPA Login Verification Code',
      preheader: 'Your one-time verification code for WPA Central Auth',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .code-box { background: #f5f5f5; border-left: 4px solid #ff6c2f; padding: 20px; margin: 20px 0; border-radius: 4px; }
    .code { font-size: 36px; font-weight: bold; letter-spacing: 4px; color: #0f3a7d; font-family: 'Courier New', monospace; }
    .code-note { color: #666; font-size: 14px; margin-top: 10px; }
    .action-button { display: inline-block; background: #0f3a7d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; }
    .security-notice { background: #e8f4f8; border: 1px solid #b3dce8; padding: 15px; border-radius: 4px; font-size: 14px; color: #333; margin: 20px 0; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 Login Verification</h1>
    </div>
    <div class="content">
      <p>Hi {{userName}},</p>
      <p>You requested to sign in to your WPA Central Auth account. Your one-time verification code is:</p>
      <div class="code-box">
        <div class="code">{{code}}</div>
        <div class="code-note">⏰ This code expires in {{expiresIn}} minutes</div>
      </div>
      <p><strong>Never share this code with anyone.</strong> WPA staff will never ask for this code.</p>
      <div class="security-notice">
        ⚠️ <strong>Didn't request this code?</strong> Your account may be at risk. If this wasn't you, immediately change your password and contact {{supportEmail}}.
      </div>
      <p>For additional security support, <a href="{{helpUrl}}">visit our help center</a>.</p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Login Verification Code

Hi {{userName}},

Your WPA Central Auth verification code is:

{{code}}

This code expires in {{expiresIn}} minutes.

SECURITY NOTICE: Never share this code. If you didn't request this, immediately change your password.

Support: {{supportEmail}}
Help: {{helpUrl}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['code', 'expiresIn'],
        optional: ['userName', 'brandName', 'supportEmail', 'helpUrl', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'email_verification',
      name: 'Email Verification',
      subject: 'Verify Your Email Address for WPA Central Auth',
      preheader: 'Complete your email verification to activate your account',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; font-size: 16px; }
    .link-text { color: #0f3a7d; word-break: break-all; font-size: 12px; font-family: monospace; background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 20px 0; }
    .info-box { background: #f0f8ff; border-left: 4px solid #0f3a7d; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>✉️ Verify Your Email</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>Thank you for creating your WPA Central Auth account. To activate your account and secure your email address, please verify your email by clicking the button below:</p>
      <a href="{{verificationLink}}" class="action-button">Verify Email Address</a>
      <p><strong>Or copy this link:</strong></p>
      <div class="link-text">{{verificationLink}}</div>
      <p style="color: #666; font-size: 14px;">⏰ <strong>This link expires in {{expiresIn}} hours</strong></p>
      <div class="info-box">
        <p><strong>⚠️ This verification was requested for:</strong></p>
        <p>Email: <strong>{{email}}</strong></p>
        <p style="font-size: 14px; margin: 10px 0 0 0;">If this isn't you or you didn't create this account, please disregard this email. Your information is safe.</p>
      </div>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Verify Your Email Address

Hello {{userName}},

Thank you for creating your account. Please verify your email address by clicking the link below:

{{verificationLink}}

This link expires in {{expiresIn}} hours.

If you didn't create this account, please disregard this email.

Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['verificationLink', 'email', 'expiresIn'],
        optional: ['userName', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'password_reset',
      name: 'Password Reset Request',
      subject: 'Reset Your WPA Central Auth Password',
      preheader: 'Click to reset your password securely',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; font-size: 16px; }
    .link-text { color: #0f3a7d; word-break: break-all; font-size: 12px; font-family: monospace; background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 20px 0; }
    .warning-box { background: #fff3cd; border-left: 4px solid #ff6c2f; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔑 Password Reset</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>We received a request to reset the password for your WPA Central Auth account. Click the button below to create a new password:</p>
      <a href="{{resetLink}}" class="action-button">Reset Your Password</a>
      <p><strong>Or copy this link:</strong></p>
      <div class="link-text">{{resetLink}}</div>
      <p style="color: #666; font-size: 14px;">⏰ <strong>This link expires in {{expiresIn}} hours</strong></p>
      <div class="warning-box">
        <p><strong>⚠️ Security Notice:</strong></p>
        <p>If you didn't request a password reset, your account may be compromised. Please:</p>
        <ol style="margin: 10px 0; padding-left: 20px;">
          <li>Click "Ignore" if this wasn't you</li>
          <li>Change your password immediately if you enabled this request</li>
          <li>Contact {{supportEmail}} if you need help</li>
        </ol>
      </div>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Password Reset Request

Hello {{userName}},

We received a request to reset your password. Click the link below to create a new password:

{{resetLink}}

This link expires in {{expiresIn}} hours.

SECURITY NOTICE: If you didn't request this, your account may be at risk. Change your password immediately and contact {{supportEmail}}.

Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['resetLink', 'expiresIn'],
        optional: ['userName', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'admin_invitation',
      name: 'Admin Invitation',
      subject: 'You\'re Invited to Join WPA Central Auth Admin Panel',
      preheader: 'Accept your invitation to manage WPA Central Auth',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; font-size: 16px; }
    .role-box { background: #f0f8ff; border: 1px solid #b3dce8; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .role-badge { display: inline-block; background: #0f3a7d; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600; margin: 3px; }
    .info-grid { margin: 20px 0; }
    .info-item { padding: 10px 0; border-bottom: 1px solid #e0e0e0; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🎉 Welcome to WPA Admin Team</h1>
    </div>
    <div class="content">
      <p>Hello {{inviteeName}},</p>
      <p>You have been invited by <strong>{{inviterName}}</strong> to join the WPA Central Auth admin panel. Accept this invitation to get started managing authentication and security settings.</p>
      <a href="{{acceptLink}}" class="action-button">Accept Invitation</a>
      <div class="role-box">
        <p style="margin: 0 0 10px 0;"><strong>📋 Your Assigned Roles:</strong></p>
        <div>{{rolesDisplay}}</div>
      </div>
      <div class="info-grid">
        <div class="info-item"><strong>Invited Email:</strong> {{inviteeEmail}}</div>
        <div class="info-item"><strong>Invitation Expires:</strong> {{expiresAt}}</div>
      </div>
      <p style="font-size: 14px; color: #666;">
        <strong>Next Steps:</strong><br>
        1. Click "Accept Invitation" above<br>
        2. Set up your account with a secure password<br>
        3. Configure your security preferences<br>
        4. Start managing the admin panel
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Welcome to WPA Admin Team

Hello {{inviteeName}},

You have been invited by {{inviterName}} to join WPA Central Auth admin panel.

Assigned Roles:
{{rolesDisplay}}

Accept your invitation here:
{{acceptLink}}

Invitation Details:
- Email: {{inviteeEmail}}
- Expires: {{expiresAt}}

Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['acceptLink', 'inviteeName', 'inviteeEmail', 'expiresAt'],
        optional: ['inviterName', 'rolesDisplay', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'welcome',
      name: 'Welcome to WPA',
      subject: 'Welcome to WPA Central Auth',
      preheader: 'Your account is ready to use',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 28px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .features { margin: 20px 0; }
    .feature-item { padding: 15px; margin: 10px 0; background: #f5f5f5; border-left: 4px solid #ff6c2f; border-radius: 4px; }
    .feature-item h3 { margin: 0 0 5px 0; color: #0f3a7d; font-size: 16px; }
    .feature-item p { margin: 0; font-size: 14px; color: #666; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 15px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🎊 Welcome, {{userName}}!</h1>
      <p>Your WPA Central Auth account is ready</p>
    </div>
    <div class="content">
      <p>Thank you for joining WPA Central Auth. We're excited to have you on board!</p>

      <div class="features">
        <div class="feature-item">
          <h3>🔐 Secure Authentication</h3>
          <p>Access WPA services with enterprise-grade security and multi-factor authentication.</p>
        </div>
        <div class="feature-item">
          <h3>👤 Account Management</h3>
          <p>Manage your profile, security settings, and connected apps from your account dashboard.</p>
        </div>
        <div class="feature-item">
          <h3>🛡️ Security First</h3>
          <p>Your data is protected with encryption and regular security audits.</p>
        </div>
      </div>

      <p><strong>Get Started:</strong></p>
      <a href="{{dashboardUrl}}" class="action-button">Go to Dashboard</a>

      <p style="font-size: 14px; color: #666; margin-top: 30px;">
        <strong>Need help?</strong> Visit our <a href="{{helpUrl}}" style="color: #0f3a7d;">help center</a> or contact <a href="mailto:{{supportEmail}}" style="color: #0f3a7d;">{{supportEmail}}</a>
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Welcome to WPA Central Auth, {{userName}}!

Thank you for joining WPA. Your account is now active and ready to use.

FEATURES:
- Secure authentication with multi-factor support
- Complete account management dashboard
- Enterprise-grade security

Get started: {{dashboardUrl}}

Help: {{helpUrl}}
Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: [],
        optional: ['userName', 'dashboardUrl', 'brandName', 'supportEmail', 'helpUrl', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'login_alert',
      name: 'Login Alert / Suspicious Activity',
      subject: 'New Login Alert - WPA Central Auth',
      preheader: 'Review your account security',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #d9534f 0%, #c9302c 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .alert-box { background: #fff3cd; border: 2px solid #ffc107; padding: 20px; margin: 20px 0; border-radius: 4px; }
    .alert-box h3 { margin: 0 0 10px 0; color: #856404; }
    .login-details { background: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 4px; font-family: monospace; font-size: 13px; }
    .action-button { display: inline-block; background: #0f3a7d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 15px 5px 15px 0; font-weight: 600; }
    .button-danger { background: #d9534f; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 New Login Detected</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>We detected a new login to your WPA Central Auth account. Please review the details below:</p>

      <div class="login-details">
        <div><strong>Time:</strong> {{loginTime}}</div>
        <div><strong>Location:</strong> {{location}}</div>
        <div><strong>IP Address:</strong> {{ipAddress}}</div>
        <div><strong>Device:</strong> {{deviceInfo}}</div>
      </div>

      <div class="alert-box">
        <h3>⚠️ Was this you?</h3>
        <p>If you recognize this login, no action is needed. If you don't recognize this activity, secure your account immediately:</p>
      </div>

      <a href="{{securityUrl}}" class="action-button">Review Activity</a>
      <a href="{{changePasswordUrl}}" class="action-button button-danger">Change Password</a>

      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        <strong>Additional Security:</strong><br>
        • Review your account activity: <a href="{{securityUrl}}" style="color: #0f3a7d;">{{securityUrl}}</a><br>
        • Revoke suspicious sessions<br>
        • Enable multi-factor authentication<br>
        • Contact support if needed
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `New Login Detected

Hello {{userName}},

We detected a new login to your account:

Time: {{loginTime}}
Location: {{location}}
IP Address: {{ipAddress}}
Device: {{deviceInfo}}

WAS THIS YOU?
If yes, no action is needed.
If no, change your password immediately:

{{changePasswordUrl}}

Security: {{securityUrl}}
Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['loginTime', 'location', 'ipAddress', 'deviceInfo'],
        optional: ['userName', 'securityUrl', 'changePasswordUrl', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'password_changed',
      name: 'Password Changed Confirmation',
      subject: 'Your Password Has Been Changed',
      preheader: 'Confirmation of your password change',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #5cb85c 0%, #4cae4c 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .success-box { background: #dff0d8; border: 1px solid #d6e9c6; padding: 15px; margin: 20px 0; border-radius: 4px; color: #3c763d; }
    .info-item { padding: 10px 0; border-bottom: 1px solid #e0e0e0; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>✅ Password Updated</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>Your password for WPA Central Auth has been successfully changed.</p>

      <div class="success-box">
        <p><strong>✓ Changed at:</strong> {{changedAt}}</p>
      </div>

      <p><strong>Security Reminder:</strong></p>
      <ul>
        <li>Never share your password with anyone</li>
        <li>Use a strong, unique password</li>
        <li>Update your password regularly</li>
        <li>Enable multi-factor authentication for extra security</li>
      </ul>

      <div class="info-item" style="padding: 15px 0; border: none;">
        <p style="font-size: 14px; color: #666;">
          <strong>Didn't make this change?</strong><br>
          If someone else changed your password without permission, <a href="{{supportUrl}}" style="color: #0f3a7d;">contact support immediately</a> to secure your account.
        </p>
      </div>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Password Updated

Hello {{userName}},

Your password has been successfully changed.

Changed at: {{changedAt}}

SECURITY REMINDER:
- Use a strong, unique password
- Update your password regularly
- Enable multi-factor authentication
- Never share your password

Didn't make this change? Contact support immediately.

Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['changedAt'],
        optional: ['userName', 'supportUrl', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'security_alert',
      name: 'Security Alert',
      subject: 'Security Alert - Action Required for Your Account',
      preheader: 'Your account requires immediate attention',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #d9534f 0%, #c9302c 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .alert-critical { background: #f2dede; border-left: 4px solid #d9534f; padding: 20px; margin: 20px 0; border-radius: 4px; color: #a94442; }
    .alert-critical h3 { margin: 0 0 10px 0; }
    .action-button { display: inline-block; background: #d9534f; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 15px 0; font-weight: 600; }
    .secondary-button { background: #0f3a7d; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 Security Alert</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>

      <div class="alert-critical">
        <h3>⚠️ We Detected Suspicious Activity</h3>
        <p><strong>Alert Type:</strong> {{alertType}}</p>
        <p><strong>Detected:</strong> {{detectedAt}}</p>
        <p>{{alertDescription}}</p>
      </div>

      <p><strong>Immediate Actions:</strong></p>
      <ol>
        <li>Change your password immediately</li>
        <li>Review your active sessions and revoke unknown ones</li>
        <li>Enable or update multi-factor authentication</li>
        <li>Review your account recovery options</li>
      </ol>

      <a href="{{secureAccountUrl}}" class="action-button">Secure Your Account Now</a>
      <a href="{{reviewActivityUrl}}" class="action-button secondary-button">Review Activity</a>

      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        <strong>Need Help?</strong><br>
        Contact our security team immediately: <a href="mailto:security@{{domain}}" style="color: #0f3a7d;">security@{{domain}}</a><br>
        Or call: {{supportPhone}}
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Security Alert

Hello {{userName}},

We detected suspicious activity on your account.

Alert Type: {{alertType}}
Detected: {{detectedAt}}

{{alertDescription}}

IMMEDIATE ACTIONS:
1. Change your password
2. Review active sessions
3. Enable multi-factor authentication
4. Check account recovery options

Secure account: {{secureAccountUrl}}
Review activity: {{reviewActivityUrl}}

Security Team: security@{{domain}}
Support: {{supportPhone}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['alertType', 'detectedAt', 'alertDescription'],
        optional: ['userName', 'secureAccountUrl', 'reviewActivityUrl', 'domain', 'supportPhone', 'brandName', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'account_suspended',
      name: 'Account Suspended',
      subject: 'Your WPA Account Has Been Suspended',
      preheader: 'Your account access has been restricted',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #d9534f 0%, #c9302c 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .notice-box { background: #f2dede; border-left: 4px solid #d9534f; padding: 20px; margin: 20px 0; border-radius: 4px; color: #a94442; }
    .action-button { display: inline-block; background: #0f3a7d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 15px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>⛔ Account Suspended</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>

      <div class="notice-box">
        <p><strong>Your WPA Central Auth account has been suspended.</strong></p>
        <p><strong>Reason:</strong> {{suspensionReason}}</p>
        <p><strong>Effective:</strong> {{suspensionDate}}</p>
      </div>

      <p>Your account access has been restricted. You will not be able to:</p>
      <ul>
        <li>Sign in to your account</li>
        <li>Access applications connected to WPA</li>
        <li>Manage your profile or security settings</li>
      </ul>

      <p><strong>What You Can Do:</strong></p>
      <ol>
        <li>Review the suspension reason above</li>
        <li>Address the issue (e.g., update compliance information, resolve payment)</li>
        <li>Contact our support team to request reinstatement</li>
      </ol>

      <a href="{{appealUrl}}" class="action-button">Request Account Review</a>

      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        <strong>Questions?</strong><br>
        Contact support: <a href="mailto:{{supportEmail}}" style="color: #0f3a7d;">{{supportEmail}}</a><br>
        Appeal process: {{helpUrl}}
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Account Suspended

Hello {{userName}},

Your WPA account has been suspended.

Reason: {{suspensionReason}}
Effective: {{suspensionDate}}

You cannot:
- Sign in to your account
- Access connected applications
- Manage your profile

To appeal this decision:
{{appealUrl}}

Support: {{supportEmail}}
Help: {{helpUrl}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['suspensionReason', 'suspensionDate'],
        optional: ['userName', 'appealUrl', 'brandName', 'supportEmail', 'helpUrl', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'account_reactivated',
      name: 'Account Reactivated',
      subject: 'Your WPA Account Has Been Reactivated',
      preheader: 'Welcome back! Your account is active again',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #5cb85c 0%, #4cae4c 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .success-box { background: #dff0d8; border: 1px solid #d6e9c6; padding: 15px; margin: 20px 0; border-radius: 4px; color: #3c763d; }
    .action-button { display: inline-block; background: #5cb85c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 15px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🎉 Welcome Back!</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>

      <div class="success-box">
        <p>✅ <strong>Your WPA account has been reactivated and is now fully active.</strong></p>
        <p><strong>Reactivated:</strong> {{reactivationDate}}</p>
      </div>

      <p>You can now:</p>
      <ul>
        <li>Sign in to your account</li>
        <li>Access all WPA applications</li>
        <li>Manage your profile and security settings</li>
        <li>Use all features of WPA Central Auth</li>
      </ul>

      <a href="{{loginUrl}}" class="action-button">Sign In Now</a>

      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        <strong>First Time Back?</strong><br>
        Review your security settings and update your password to ensure your account is protected: <a href="{{securityUrl}}" style="color: #0f3a7d;">{{securityUrl}}</a>
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Account Reactivated

Hello {{userName}},

Your WPA account has been reactivated!

Reactivated: {{reactivationDate}}

You can now:
- Sign in to your account
- Access all WPA applications
- Manage your profile
- Use all WPA features

Sign in: {{loginUrl}}

Recommend updating your security settings: {{securityUrl}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['reactivationDate'],
        optional: ['userName', 'loginUrl', 'securityUrl', 'brandName', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'role_updated',
      name: 'Role/Permissions Updated',
      subject: 'Your WPA Account Roles Have Been Updated',
      preheader: 'Your account permissions have changed',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .role-box { background: #f0f8ff; border: 1px solid #b3dce8; padding: 15px; margin: 15px 0; border-radius: 4px; }
    .role-badge { display: inline-block; background: #0f3a7d; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: 600; margin: 3px; }
    .action-button { display: inline-block; background: #0f3a7d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 15px 0; font-weight: 600; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>📋 Role Update</h1>
    </div>
    <div class="content">
      <p>Hello {{userName}},</p>
      <p>Your account roles and permissions have been updated. Please review your new access level below:</p>

      <div class="role-box">
        <p><strong>📍 Current Roles:</strong></p>
        <div>{{currentRoles}}</div>
      </div>

      {{#if previousRoles}}
      <div class="role-box" style="background: #fff3cd; border-color: #ffc107;">
        <p><strong>📍 Previous Roles:</strong></p>
        <div>{{previousRoles}}</div>
      </div>
      {{/if}}

      <p><strong>Updated:</strong> {{updatedAt}}</p>
      <p><strong>Updated By:</strong> {{updatedBy}}</p>

      <p style="font-size: 14px; color: #666; margin: 20px 0;">
        If you have questions about your new permissions or believe this is an error, please contact your administrator or support.
      </p>

      <a href="{{accountUrl}}" class="action-button">Review Account Permissions</a>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Role Update

Hello {{userName}},

Your account roles have been updated.

Current Roles:
{{currentRoles}}

{{#if previousRoles}}
Previous Roles:
{{previousRoles}}
{{/if}}

Updated: {{updatedAt}}
Updated By: {{updatedBy}}

Review permissions: {{accountUrl}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['currentRoles', 'updatedAt', 'updatedBy'],
        optional: ['userName', 'previousRoles', 'accountUrl', 'brandName', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'magic_link',
      name: 'Magic Link / Passwordless Login',
      subject: 'Your Passwordless Login Link for WPA',
      preheader: 'Click to sign in without a password',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .action-button { display: inline-block; background: #ff6c2f; color: white; padding: 14px 32px; text-decoration: none; border-radius: 4px; margin: 20px 0; font-weight: 600; font-size: 16px; }
    .link-text { color: #0f3a7d; word-break: break-all; font-size: 12px; font-family: monospace; background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 20px 0; }
    .info-box { background: #f0f8ff; border-left: 4px solid #0f3a7d; padding: 15px; margin: 20px 0; border-radius: 4px; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 Passwordless Sign In</h1>
    </div>
    <div class="content">
      <p>Hi {{email}},</p>
      <p>Click the button below to sign in to your WPA account. No password needed!</p>
      <a href="{{magicLink}}" class="action-button">Sign In to WPA</a>
      <p style="color: #666; font-size: 14px; margin-top: 15px;"><strong>Or copy this link:</strong></p>
      <div class="link-text">{{magicLink}}</div>
      <p style="color: #666; font-size: 14px;">⏰ <strong>This link expires in {{expiresIn}} minutes</strong></p>

      <div class="info-box">
        <p><strong>Why this link?</strong></p>
        <p>Passwordless authentication is more secure than passwords. This unique link works only for you and can only be used once.</p>
      </div>

      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        <strong>Didn't request this link?</strong> You can safely ignore this email. Your account is secure.
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Passwordless Sign In

Hi {{email}},

Click this link to sign in without a password:

{{magicLink}}

Link expires in {{expiresIn}} minutes.

Why passwordless? It's more secure than passwords. This link works only for you.

Didn't request this? Ignore this email—your account is secure.

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['magicLink', 'email', 'expiresIn'],
        optional: ['brandName', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    },
    {
      key: 'two_factor_code',
      name: 'Two-Factor Authentication Code',
      subject: 'Your WPA Two-Factor Code',
      preheader: 'Complete authentication with your verification code',
      htmlBody: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; }
    .header { background: linear-gradient(135deg, #0f3a7d 0%, #1a5ba8 100%); color: white; padding: 30px 20px; text-align: center; }
    .header h1 { margin: 0; font-size: 24px; font-weight: 600; }
    .content { padding: 30px 20px; }
    .code-box { background: #f5f5f5; border-left: 4px solid #ff6c2f; padding: 20px; margin: 20px 0; border-radius: 4px; }
    .code { font-size: 40px; font-weight: bold; letter-spacing: 6px; color: #0f3a7d; font-family: 'Courier New', monospace; }
    .code-note { color: #666; font-size: 14px; margin-top: 10px; }
    .security-notice { background: #e8f4f8; border: 1px solid #b3dce8; padding: 15px; border-radius: 4px; font-size: 14px; color: #333; margin: 20px 0; }
    .footer { background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; border-top: 1px solid #e0e0e0; }
    .footer a { color: #0f3a7d; text-decoration: none; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🔐 Two-Factor Code</h1>
    </div>
    <div class="content">
      <p>Hi {{userName}},</p>
      <p>Your two-factor authentication code is:</p>
      <div class="code-box">
        <div class="code">{{code}}</div>
        <div class="code-note">⏰ This code expires in {{expiresIn}} seconds</div>
      </div>
      <p><strong>Enter this code to complete your sign in.</strong></p>
      <div class="security-notice">
        ⚠️ <strong>Never share this code.</strong> A WPA employee will never ask for this code. If someone claims to be from WPA and asks for this code, it's likely a scam.
      </div>
      <p style="font-size: 14px; color: #666; margin-top: 20px;">
        <strong>Didn't request this code?</strong> Someone may be trying to access your account. Change your password immediately and contact support.
      </p>
    </div>
    <div class="footer">
      <p>{{legalDisclaimer}}</p>
      <p><a href="{{privacyUrl}}">Privacy Policy</a> | <a href="{{termsUrl}}">Terms of Service</a> | <a href="{{contactUrl}}">Contact Us</a></p>
      <p>© 2024 {{brandName}}. All rights reserved.</p>
    </div>
  </div>
</body>
</html>`,
      textBody: `Two-Factor Authentication Code

Hi {{userName}},

Your two-factor code is:

{{code}}

Code expires in {{expiresIn}} seconds.

SECURITY: Never share this code. Never give it to anyone claiming to be from WPA.

Didn't request this? Change your password immediately.

Support: {{supportEmail}}

© 2024 {{brandName}}. All rights reserved.`,
      variables: {
        required: ['code', 'expiresIn'],
        optional: ['userName', 'brandName', 'supportEmail', 'privacyUrl', 'termsUrl', 'contactUrl', 'legalDisclaimer']
      }
    }
  ];

  // Check if force reseed flag is set
  const forceTemplateReseed = process.env.FORCE_RESEED === 'true';

  for (const template of emailTemplates) {
    const locale = template.locale ?? 'en';
    const clientId = template.clientId ?? null;
    const existingTemplate = await prisma.emailTemplate.findFirst({
      where: {
        key: template.key,
        locale,
        clientId,
      },
      select: { id: true, updatedByAdminId: true }
    });

    // If template exists and was edited by admin (updatedByAdminId is set), skip unless force reseed
    if (existingTemplate && existingTemplate.updatedByAdminId && !forceTemplateReseed) {
      console.log(`  ⏭️  ${template.key} - Already customized by admin (skipped). Use FORCE_RESEED=true to override.`);
      continue;
    }

    if (existingTemplate) {
      await prisma.emailTemplate.update({
        where: { id: existingTemplate.id },
        data: forceTemplateReseed ? {
          name: template.name,
          subject: template.subject,
          preheader: template.preheader,
          htmlBody: template.htmlBody,
          textBody: template.textBody,
          variables: template.variables as any,
          isActive: true
        } : {}
      });
      console.log(`  ✅ ${template.key}`);
      continue;
    }

    await prisma.emailTemplate.create({
      data: {
        key: template.key,
        locale,
        clientId,
        name: template.name,
        subject: template.subject,
        preheader: template.preheader,
        htmlBody: template.htmlBody,
        textBody: template.textBody,
        variables: template.variables as any,
        isActive: true,
        updatedByAdminId: seededAdmin?.id,
      }
    });
    console.log(`  ✅ ${template.key}`);
  }
  console.log('Email templates seeded.');

  console.log('Seeding completed successfully.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
