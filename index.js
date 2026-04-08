/**
 * agentshield-js
 * Official SDK for the AgentShield security protocol
 * https://agentshield.win
 */

const DEFAULT_BASE_URL = "https://agentshield.win";

class AgentShield {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || DEFAULT_BASE_URL;
  }

  async _request(path, options = {}) {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      ...options
    });
    if (!res.ok) throw new Error(`AgentShield error ${res.status}: ${await res.text()}`);
    return res.json();
  }

  /**
   * Verify a smart contract before interacting.
   * @param {string} contract - Contract address (0x...)
   * @param {string|number} chain - Chain ID (default: 1 = Ethereum)
   * @param {boolean} force - Skip cache and force fresh verification
   * @returns {Promise<VerifyResult>}
   */
  async verify(contract, chain = 1, force = false) {
    const params = new URLSearchParams({ contract, chain: String(chain) });
    if (force) params.set("force", "true");
    return this._request(`/verify?${params}`);
  }

  /**
   * Monitor a wallet address for threats.
   * @param {string} wallet - Wallet address to monitor
   * @param {string} webhookUrl - URL to receive threat alerts (recommended)
   * @param {string|number} chain - Chain ID
   * @returns {Promise<MonitorResult>}
   */
  async monitor(wallet, webhookUrl = null, chain = 1) {
    return this._request("/monitor", {
      method: "POST",
      body: JSON.stringify({ wallet, webhook_url: webhookUrl, chain: String(chain) })
    });
  }

  /**
   * Freeze wallet interactions immediately.
   * @param {string} wallet - Wallet address to freeze
   * @param {string} reason - Reason for freeze
   * @returns {Promise<FreezeResult>}
   */
  async freeze(wallet, reason = "Threat detected") {
    return this._request("/freeze", {
      method: "POST",
      body: JSON.stringify({ wallet, reason })
    });
  }

  /**
   * Check if a wallet is monitored or frozen.
   * @param {string} wallet - Wallet address
   * @returns {Promise<CheckResult>}
   */
  async check(wallet) {
    return this._request(`/check?wallet=${encodeURIComponent(wallet)}`);
  }

  /**
   * Get live protocol statistics.
   * @returns {Promise<StatsResult>}
   */
  async stats() {
    return this._request("/stats");
  }

  /**
   * Safe interaction helper — verify before acting.
   * Returns true if safe, throws if dangerous.
   * @param {string} contract
   * @param {string|number} chain
   */
  async safeInteract(contract, chain = 1) {
    const result = await this.verify(contract, chain);
    if (result.risk_level === "CRITICAL" || result.is_honeypot) {
      throw new Error(`[AgentShield] BLOCKED: ${result.message} — ${result.recommendation}`);
    }
    if (result.risk_level === "HIGH") {
      console.warn(`[AgentShield] WARNING: ${result.message}`);
    }
    return result;
  }
}

module.exports = AgentShield;
module.exports.default = AgentShield;
