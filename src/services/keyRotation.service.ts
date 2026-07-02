import { prisma } from '../lib/db.js';
import { decryptCredentialPayload, encryptCredentialPayload, getActiveCredentialEncryptionVersion } from '../lib/credentialEncryption.js';

export type CredentialReencryptionSummary = {
  activeVersion: number;
  scanned: number;
  candidates: number;
  updated: number;
  failed: number;
  dryRun: boolean;
};

function isCurrentVersion(version: number | null | undefined) {
  return (version ?? 0) === getActiveCredentialEncryptionVersion();
}

export async function reencryptProviderCredentials(opts?: {
  dryRun?: boolean;
  batchSize?: number;
}): Promise<CredentialReencryptionSummary> {
  const dryRun = opts?.dryRun ?? false;
  const batchSize = Math.max(1, Math.min(opts?.batchSize ?? 100, 1000));
  const activeVersion = getActiveCredentialEncryptionVersion();

  let cursor: string | undefined;
  let scanned = 0;
  let candidates = 0;
  let updated = 0;
  let failed = 0;

  while (true) {
    const rows = await prisma.communicationProviderCredential.findMany({
      take: batchSize,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
      orderBy: { id: 'asc' },
      select: {
        id: true,
        encryptedSecrets: true,
        encryptionKeyVersion: true,
      },
    });

    if (!rows.length) break;
    scanned += rows.length;

    for (const row of rows) {
      cursor = row.id;
      if (isCurrentVersion(row.encryptionKeyVersion)) continue;
      candidates += 1;

      try {
        const payload = decryptCredentialPayload(row.encryptedSecrets as any);
        if (!dryRun) {
          const encryptedSecrets = encryptCredentialPayload(payload);
          await prisma.communicationProviderCredential.update({
            where: { id: row.id },
            data: {
              encryptedSecrets,
              encryptionKeyVersion: encryptedSecrets.version ?? activeVersion,
            },
          });
          updated += 1;
        }
      } catch {
        failed += 1;
      }
    }

    if (rows.length < batchSize) break;
  }

  return {
    activeVersion,
    scanned,
    candidates,
    updated,
    failed,
    dryRun,
  };
}
