const seenIds = new Set<string>();

export function triggerCriticalNotification(
  id: string | number,
  title: string,
  body: string,
): void {
  const key = String(id);
  if (seenIds.has(key)) return;
  seenIds.add(key);

  if (!("Notification" in window)) return;
  if (Notification.permission === "granted") {
    new Notification(title, { body });
  } else if (Notification.permission !== "denied") {
    Notification.requestPermission().then((perm) => {
      if (perm === "granted") {
        new Notification(title, { body });
      }
    });
  }

  // GC old entries after 1 hour
  setTimeout(() => seenIds.delete(key), 3600_000);
}
