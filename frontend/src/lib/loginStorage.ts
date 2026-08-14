export const LOGIN_EMAIL_KEY = 'auth-last-email'

export function getSavedEmail(): string {
  try {
    return localStorage.getItem(LOGIN_EMAIL_KEY) || ''
  } catch {
    return ''
  }
}

export function saveEmail(email: string): void {
  try {
    localStorage.setItem(LOGIN_EMAIL_KEY, email)
  } catch {
    // localStorage may be unavailable (private mode, quota exceeded)
  }
}
