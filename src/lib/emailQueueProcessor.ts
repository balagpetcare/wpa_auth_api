import { logger } from './logger.js'
import { sendTemplatedEmail } from './sendTemplatedEmail.js'
import { prisma } from './db.js'

interface QueueProcessorStats {
  processed: number
  successful: number
  failed: number
  retrying: number
  queueSize: number
  nextProcessTime: Date
}

let processorRunning = false
let processorInterval: NodeJS.Timeout | null = null

const PROCESS_INTERVAL_MS = 5 * 60 * 1000 // 5 minutes
const MAX_RETRIES = 3
const INITIAL_BACKOFF_MS = 60000 // 1 minute
const MAX_BACKOFF_MS = 24 * 60 * 60 * 1000 // 24 hours

function calculateNextRetryTime(attemptCount: number): Date {
  // Exponential backoff: 1min, 5min, 30min, then max
  const backoffMs = Math.min(
    INITIAL_BACKOFF_MS * Math.pow(2, attemptCount - 1),
    MAX_BACKOFF_MS
  )
  return new Date(Date.now() + backoffMs)
}

function maskSensitiveData(variables: any): any {
  if (!variables || typeof variables !== 'object') return variables
  const masked = { ...variables }
  const sensitiveKeys = ['otp', 'token', 'resetToken', 'inviteToken', 'magicLink', 'verificationToken']
  for (const key of sensitiveKeys) {
    if (key in masked) {
      const value = masked[key]
      if (typeof value === 'string' && value.length > 4) {
        masked[key] = value.substring(0, 4) + '*'.repeat(Math.max(0, value.length - 8)) + value.substring(value.length - 4)
      }
    }
  }
  return masked
}

export async function processEmailQueue(): Promise<QueueProcessorStats> {
  if (processorRunning) {
    logger.warn('Email queue processor already running, skipping')
    return {
      processed: 0,
      successful: 0,
      failed: 0,
      retrying: 0,
      queueSize: 0,
      nextProcessTime: new Date(Date.now() + PROCESS_INTERVAL_MS),
    }
  }

  processorRunning = true
  const startTime = Date.now()
  const stats: QueueProcessorStats = {
    processed: 0,
    successful: 0,
    failed: 0,
    retrying: 0,
    queueSize: 0,
    nextProcessTime: new Date(Date.now() + PROCESS_INTERVAL_MS),
  }

  try {
    // Get pending and retrying emails that are ready to process
    const queueItems = await prisma.emailQueue.findMany({
      where: {
        OR: [
          { status: 'pending' },
          {
            status: 'retrying',
            nextRetryAt: { lte: new Date() },
          },
        ],
      },
      take: 100, // Process max 100 at a time
      orderBy: [{ status: 'asc' }, { createdAt: 'asc' }],
    })

    stats.queueSize = await prisma.emailQueue.count({
      where: { status: { in: ['pending', 'retrying', 'processing'] } },
    })

    for (const item of queueItems) {
      try {
        // Mark as processing
        await prisma.emailQueue.update({
          where: { id: item.id },
          data: { status: 'processing' },
        })

        // Prepare template variables with masked sensitive data
        const maskedVariables = maskSensitiveData(item.variables)

        // Send email
        const result = await sendTemplatedEmail({
          templateKey: item.templateKey as any,
          recipientEmail: item.recipientEmail,
          recipientName: item.recipientName || undefined,
          variables: (item.variables as any) || {},
          clientId: item.clientId || undefined,
          locale: item.locale || 'en',
        })

        if (result.success && result.sendLogId) {
          // Mark as sent
          await prisma.emailQueue.update({
            where: { id: item.id },
            data: {
              status: 'sent',
              sendLogId: result.sendLogId,
              attempt: item.attempt + 1,
            },
          })
          stats.successful++
        } else {
          throw new Error(result.error || 'Failed to send email')
        }

        stats.processed++
      } catch (error) {
        stats.processed++
        const attempt = item.attempt + 1
        const errorMsg = error instanceof Error ? error.message : String(error)

        if (attempt < MAX_RETRIES) {
          // Schedule retry with exponential backoff
          const nextRetryAt = calculateNextRetryTime(attempt)
          await prisma.emailQueue.update({
            where: { id: item.id },
            data: {
              status: 'retrying',
              attempt,
              nextRetryAt,
              lastError: errorMsg,
            },
          })
          stats.retrying++
          logger.warn(`Email queue retry scheduled: ${item.id} - attempt ${attempt}/${MAX_RETRIES}`)
        } else {
          // Max retries exceeded - mark as failed
          const sendLog = await prisma.emailSendLog.create({
            data: {
              templateKey: item.templateKey,
              locale: item.locale,
              clientId: item.clientId || undefined,
              recipientEmail: item.recipientEmail,
              recipientName: item.recipientName,
              subject: item.subject,
              variables: maskSensitiveData(item.variables),
              status: 'failed',
              deliveryStatus: 'failed',
              userId: item.userId || undefined,
              errorMessage: errorMsg,
              attemptCount: attempt,
              failedAt: new Date(),
            },
          })

          await prisma.emailQueue.update({
            where: { id: item.id },
            data: {
              status: 'failed',
              attempt,
              lastError: errorMsg,
              sendLogId: sendLog.id,
            },
          })
          stats.failed++
          logger.error(
            { error: errorMsg, queueId: item.id },
            `Email queue failed after ${attempt} attempts`
          )
        }
      }
    }

    const duration = Date.now() - startTime
    logger.info({ ...stats, durationMs: duration }, 'Email queue processing completed')

    return stats
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error)
    logger.error({ error: errorMsg }, 'Email queue processor error')
    return stats
  } finally {
    processorRunning = false
  }
}

export async function startQueueProcessor(): Promise<void> {
  if (processorInterval) {
    logger.warn('Email queue processor already started')
    return
  }

  logger.info({ intervalMs: PROCESS_INTERVAL_MS }, 'Starting email queue processor')

  // Initial run after 30 seconds
  setTimeout(() => processEmailQueue(), 30000)

  // Schedule recurring runs every PROCESS_INTERVAL_MS
  processorInterval = setInterval(() => {
    processEmailQueue().catch((error) => {
      const errorMsg = error instanceof Error ? error.message : String(error)
      logger.error({ error: errorMsg }, 'Unhandled error in email queue processor')
    })
  }, PROCESS_INTERVAL_MS)
}

export async function stopQueueProcessor(): Promise<void> {
  if (processorInterval) {
    clearInterval(processorInterval)
    processorInterval = null
    logger.info('Email queue processor stopped')
  }

  // Wait for current processing to complete
  let attempts = 0
  while (processorRunning && attempts < 30) {
    await new Promise((resolve) => setTimeout(resolve, 1000))
    attempts++
  }

  if (processorRunning) {
    logger.warn('Email queue processor did not complete within 30s, force stopping')
  }

  // Note: Do not disconnect from shared prisma instance - it's managed by the main server
}

export async function getQueueStats(): Promise<{
  total: number
  pending: number
  processing: number
  retrying: number
  sent: number
  failed: number
  oldestPendingAge?: number
}> {
  const [total, pending, processing, retrying, sent, failed] = await Promise.all([
    prisma.emailQueue.count(),
    prisma.emailQueue.count({ where: { status: 'pending' } }),
    prisma.emailQueue.count({ where: { status: 'processing' } }),
    prisma.emailQueue.count({ where: { status: 'retrying' } }),
    prisma.emailQueue.count({ where: { status: 'sent' } }),
    prisma.emailQueue.count({ where: { status: 'failed' } }),
  ])

  const oldestPending = await prisma.emailQueue.findFirst({
    where: { status: 'pending' },
    orderBy: { createdAt: 'asc' },
    select: { createdAt: true },
  })

  return {
    total,
    pending,
    processing,
    retrying,
    sent,
    failed,
    oldestPendingAge: oldestPending ? Date.now() - oldestPending.createdAt.getTime() : undefined,
  }
}

export async function retryFailedEmail(queueId: string): Promise<boolean> {
  const queueItem = await prisma.emailQueue.findUnique({
    where: { id: queueId },
  })

  if (!queueItem || queueItem.status !== 'failed') {
    logger.warn(`Cannot retry email: ${queueId} - not in failed status`)
    return false
  }

  await prisma.emailQueue.update({
    where: { id: queueId },
    data: {
      status: 'pending',
      attempt: 0,
      nextRetryAt: null,
      lastError: null,
    },
  })

  logger.info(`Email queue item reset for retry: ${queueId}`)
  return true
}

export async function deleteDuplicateQueueItems(templateKey: string, recipientEmail: string, ageMinutes = 1440): Promise<number> {
  const cutoffTime = new Date(Date.now() - ageMinutes * 60 * 1000)

  const duplicates = await prisma.emailQueue.findMany({
    where: {
      templateKey,
      recipientEmail,
      status: 'pending',
      createdAt: { lt: cutoffTime },
    },
    orderBy: { createdAt: 'desc' },
    skip: 1, // Keep the most recent one
  })

  if (duplicates.length === 0) {
    return 0
  }

  const result = await prisma.emailQueue.deleteMany({
    where: {
      id: { in: duplicates.map((d) => d.id) },
    },
  })

  logger.info(`Deleted ${result.count} duplicate email queue items: ${templateKey} to ${recipientEmail}`)
  return result.count
}
