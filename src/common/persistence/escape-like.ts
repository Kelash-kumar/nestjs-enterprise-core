export function escapeLike(value: string): string {
  return value.trim().replace(/[\\%_]/g, '\\$&');
}
