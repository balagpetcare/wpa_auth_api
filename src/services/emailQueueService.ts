import { prisma } from '../lib/db.js'
import { AppError } from '../lib/errors.js'

interface QueueEmailParams {
  templateKey: string
  locale?: string
  clientId?: string
  recipientEmail: string
  recipientName?: string
  subject: string
  variables?: Record<string, any>
  userId?: string
  maxRetries?: number
}

const RETRY_DELAYS = {
  1: 5 * 60 * 1000, // 5 minutes
  2: 15 * 60 * 1000, // 15 minutes
  3: 60 * 60 * 1000, // 1 hour
}

export class EmailQueueService {
  /**
   * Queue an email for delivery
   */
  static async enqueueEmail(params: QueueEmailParams) {
    try {
      const queueItem = await prisma.emailQueue.create({
        data: {
          templateKey: params.templateKey,
          locale: params.locale || 'en',
          clientId: params.clientId,
          recipientEmail: params.recipientEmail,
          recipientName: params.recipientName,
          subject: params.subject,
          variables: params.variables,
          status: 'pending',
          maxRetries: params.maxRetries || 3,
          userId: params.userId,
        },
      })

      return queueItem
    } catch (error) {
      throw new AppError(
        `Failed to queue email: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'QUEUE_ERROR',
        500
      )
    }
  }

  /**
   * Get pending emails for delivery
   */
  static async getPendingEmails(limit = 10) {
    try {
      return await prisma.emailQueue.findMany({
        where: {
          status: { in: ['pending', 'retrying'] },
          OR: [
            { nextRetryAt: null },
            { nextRetryAt: { lte: new Date() } },
          ],
        },
        orderBy: { createdAt: 'asc' },
        take: limit,
      })
    } catch (error) {
      throw new AppError(
        'Failed to fetch pending emails',
        'QUEUE_ERROR',
        500
      )
    }
  }

  /**
   * Mark email as processing
   */
  static async markProcessing(queueId: string) {
    try {
      return await prisma.emailQueue.update({
        where: { id: queueId },
        data: { status: 'processing' },
      })
    } catch (error) {
      throw new AppError('Failed to update queue status', 'QUEUE_ERROR', 500)
    }
  }

  /**
   * Mark email as sent and create send log
   */
  static async markSent(
    queueId: string,
    sendLogId: string,
    metadata?: Record<string, any>
  ) {
    try {
      await prisma.emailQueue.update({
        where: { id: queueId },
        data: {
          status: 'sent',
          sendLogId,
          metadata,
          updatedAt: new Date(),
        },
      })

      await prisma.emailSendLog.update({
        where: { id: sendLogId },
        data: {
          status: 'sent',
          deliveryStatus: 'sent',
          sentAt: new Date(),
        },
      })
    } catch (error) {
      throw new AppError('Failed to mark email as sent', 'QUEUE_ERROR', 500)
    }
  }

  /**
   * Mark email as failed and schedule retry if applicable
   */
  static async markFailed(
    queueId: string,
    error: string,
    sendLogId?: string
  ) {
    try {
      const queueItem = await prisma.emailQueue.findUnique({
        where: { id: queueId },
      })

      if (!queueItem) {
        throw new AppError('Queue item not found', 'NOT_FOUND', 404)
      }

      const nextAttempt = queueItem.attempt + 1
      const shouldRetry = nextAttempt <= queueItem.maxRetries
      const delayMs =
        RETRY_DELAYS[nextAttempt as keyof typeof RETRY_DELAYS] || 24 * 60 * 60 * 1000

      await prisma.emailQueue.update({
        where: { id: queueId },
        data: {
          status: shouldRetry ? 'retrying' : 'failed',
          attempt: nextAttempt,
          lastError: error,
          nextRetryAt: shouldRetry ? new Date(Date.now() + delayMs) : null,
          updatedAt: new Date(),
        },
      })

      if (sendLogId) {
        await prisma.emailSendLog.update({
          where: { id: sendLogId },
          data: {
            status: shouldRetry ? 'retrying' : 'failed',
            deliveryStatus: 'failed',
            errorMessage: error,
            failedAt: new Date(),
            attemptCount: nextAttempt,
          },
        })
      }

      return { shouldRetry, nextRetryAt: shouldRetry ? new Date(Date.now() + delayMs) : null }
    } catch (error) {
      throw new AppError(
        'Failed to mark email as failed',
        'QUEUE_ERROR',
        500
      )
    }
  }

  /**
   * Get queue statistics
   */
  static async getQueueStats() {
    try {
      return await prisma.emailQueue.groupBy({
        by: ['status'],
        _count: true,
      })
    } catch (error) {
      throw new AppError('Failed to fetch queue stats', 'QUEUE_ERROR', 500)
    }
  }

  /**
   * Get retry history for an email
   */
  static async getRetryHistory(templateKey: string, recipientEmail: string) {
    try {
      return await prisma.emailQueue.findMany({
        where: {
          templateKey,
          recipientEmail,
        },
        orderBy: { createdAt: 'desc' },
        take: 10,
      })
    } catch (error) {
      throw new AppError('Failed to fetch retry history', 'QUEUE_ERROR', 500)
    }
  }

  /**
   * Manually retry a failed email
   */
  static async retryEmail(queueId: string) {
    try {
      return await prisma.emailQueue.update({
        where: { id: queueId },
        data: {
          status: 'pending',
          attempt: 0,
          lastError: null,
          nextRetryAt: null,
          updatedAt: new Date(),
        },
      })
    } catch (error) {
      throw new AppError('Failed to retry email', 'QUEUE_ERROR', 500)
    }
  }

  /**
   * Clean up old completed queue items
   */
  static async cleanupOldItems(days = 30) {
    try {
      const cutoffDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000)

      return await prisma.emailQueue.deleteMany({
        where: {
          status: 'sent',
          createdAt: { lt: cutoffDate },
        },
      })
    } catch (error) {
      throw new AppError('Failed to cleanup old queue items', 'QUEUE_ERROR', 500)
    }
  }
}
