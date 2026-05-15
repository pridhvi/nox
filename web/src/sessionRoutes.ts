export function scopedSessionPath(selectedSessionID: string, suffix: string) {
  return selectedSessionID ? `/sessions/${selectedSessionID}${suffix}` : suffix || "/";
}
