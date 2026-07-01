export class AppError extends Error {
  constructor(
    public readonly message: string,
    public readonly code: string,
    public readonly status: number = 400,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function errBody(message: string, code: string) {
  return { success: false as const, message, code };
}
