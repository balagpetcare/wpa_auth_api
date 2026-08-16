import test from 'node:test'
import assert from 'node:assert/strict'
import { prisma } from '../../lib/db.js'
import { clearArchivedNotifications, getMyUnreadNotificationCount, listMyNotifications, markNotificationRead } from './admin.service.js'

function makeNotification(overrides: Record<string, unknown> = {}) {
  return {
    id: 'notification-1',
    title: 'Test notification',
    message: 'Hello world',
    severity: 'INFO',
    category: 'SYSTEM',
    actionUrl: null,
    readAt: null,
    dismissedAt: null,
    createdAt: new Date('2026-08-12T00:00:00.000Z'),
    ...overrides,
  } as any
}

test('listMyNotifications uses the live readAt/dismissedAt schema and derives status', async () => {
  const originalFindMany = prisma.adminNotification.findMany
  const originalCount = prisma.adminNotification.count
  const findManyCalls: any[] = []
  const countCalls: any[] = []

  ;(prisma.adminNotification.findMany as any) = async (args: any) => {
    findManyCalls.push(args)
    return [
      makeNotification({ id: 'n1', readAt: null, dismissedAt: null }),
      makeNotification({ id: 'n2', readAt: new Date('2026-08-12T00:01:00.000Z'), dismissedAt: null }),
      makeNotification({ id: 'n3', readAt: new Date('2026-08-12T00:02:00.000Z'), dismissedAt: new Date('2026-08-12T00:03:00.000Z') }),
    ]
  }
  ;(prisma.adminNotification.count as any) = async (args: any) => {
    countCalls.push(args)
    return countCalls.length <= 2 ? 1 : countCalls.length - 1
  }

  try {
    const result = await listMyNotifications({
      userId: 'admin-1',
      status: 'unread',
      limit: 5,
    })

    assert.equal(findManyCalls.length, 1)
    assert.equal(findManyCalls[0].where.dismissedAt, null)
    assert.equal(findManyCalls[0].where.readAt, null)
    assert.deepEqual(result.items.map((item: any) => item.status), ['UNREAD', 'READ', 'ARCHIVED'])
    assert.equal(result.unreadCount, 1)
    assert.equal(result.totalCount, 1)
    assert.equal(result.readCount, 2)
    assert.equal(result.archivedCount, 3)
  } finally {
    ;(prisma.adminNotification.findMany as any) = originalFindMany
    ;(prisma.adminNotification.count as any) = originalCount
  }
})

test('markNotificationRead persists readAt without requiring a status column', async () => {
  const originalFindFirst = prisma.adminNotification.findFirst
  const originalUpdate = prisma.adminNotification.update

  ;(prisma.adminNotification.findFirst as any) = async () => makeNotification()
  ;(prisma.adminNotification.update as any) = async (args: any) => ({
    ...makeNotification({ readAt: new Date('2026-08-12T00:10:00.000Z') }),
    ...args.data,
  })

  try {
    const updated = await markNotificationRead('admin-1', 'notification-1')
    assert.equal((updated as any).status, 'READ')
    assert.ok((updated as any).readAt instanceof Date)
  } finally {
    ;(prisma.adminNotification.findFirst as any) = originalFindFirst
    ;(prisma.adminNotification.update as any) = originalUpdate
  }
})

test('clearArchivedNotifications targets dismissedAt rows', async () => {
  const originalDeleteMany = prisma.adminNotification.deleteMany
  let deleteArgs: any = null
  ;(prisma.adminNotification.deleteMany as any) = async (args: any) => {
    deleteArgs = args
    return { count: 4 }
  }

  try {
    const result = await clearArchivedNotifications('admin-1')
    assert.equal(result.deletedCount, 4)
    assert.equal(deleteArgs.where.dismissedAt.not !== undefined, true)
  } finally {
    ;(prisma.adminNotification.deleteMany as any) = originalDeleteMany
  }
})

test('getMyUnreadNotificationCount counts only unread visible notifications', async () => {
  const originalCount = prisma.adminNotification.count
  let countArgs: any = null
  ;(prisma.adminNotification.count as any) = async (args: any) => {
    countArgs = args
    return 7
  }

  try {
    const result = await getMyUnreadNotificationCount('admin-1')
    assert.equal(result.unreadCount, 7)
    assert.equal(countArgs.where.dismissedAt, null)
    assert.equal(countArgs.where.readAt, null)
  } finally {
    ;(prisma.adminNotification.count as any) = originalCount
  }
})
