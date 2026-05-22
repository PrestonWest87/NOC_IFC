import { useState } from "react";
import axios from "axios";

export function BidirectionalCommands() {
  const [siteId, setSiteId] = useState<number>(0);
  const [sending, setSending] = useState(false);

  async function handleAcknowledge() {
    if (!siteId) return;
    setSending(true);
    try {
      await axios.patch(`/api/v1/aiops/sites/${siteId}/acknowledge`);
    } catch {
      // ignore
    } finally {
      setSending(false);
    }
  }

  return (
    <div>
      <input
        type="number"
        value={siteId}
        onChange={(e) => setSiteId(Number(e.target.value))}
        placeholder="Site ID"
      />
      <button onClick={handleAcknowledge} disabled={sending}>
        {sending ? "Acknowledging..." : "Acknowledge Site"}
      </button>
    </div>
  );
}
