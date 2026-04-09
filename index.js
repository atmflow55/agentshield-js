/**
 * agentshield-js
 * Official SDK for the AgentShield security protocol
 * https://agentshield.win
 */

const DEFAULT_BASE_URL = "https://agentshield.win";

class AgentShield {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || DEFAULT_BASE_URL;
    this.apiKey = options.apiKey || null;
  }

  async _request(path, options = {}) {
    const headers = {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...options.headers,
    };
    if (this.apiKey) headers["X-API-Key"] = this.apiKey;

    const res = await fetch(`${this.baseUrl}${path}`, { ...options, headers });
    if (!res.ok) throw new Error(`AgentShield error ${res.status}: ${await res.text()}`);
    return res.json();
  }

  /**
   * Verify a smart contract before interacting.
   * @param {string} contract - Contract address (0x...)
   * @param {string|number} chain - Chain ID (default: 1 = Ethereum)
   * @param {boolean} force - Skip cache and force fresh verification
   * @returns {Promise<Object>}
   */
  async verify(contract, chain = 1, force = false) {
    const params = new URLSearchParams({ contract, chain: String(chain) });
    if (force) params.set("force", "true");
    return this._request(`/verify?${params}`);
  }

  /**
   * Deep forensic analysis: ownership, permissions, exploit patterns, bytecode, risk breakdown.
   * @param {string} contract - Contract address (0x...)
   * @param {string|number} chain - Chain ID (default: 1 = Ethereum)
   * @returns {Promise<Object>}
   */
  async deepScan(contract, chain = 1) {
    const params = new URLSearchParams({ contract, chain: String(chain) });
    return this._request(`/deep-scan?${params}`);
  }

  /**
   * Full threat detection scan: honeypots, rug pulls, mint/freeze authority, proxy backdoors,
   * tax manipulation, blacklist functions, liquidity analysis, holder concentration. 14+ checks.
   * @param {string} contract - Token/contract address
   * @param {string} chain - Chain name: solana, ethereum, base, bsc, polygon, arbitrum, optimism
   * @returns {Promise<Object>}
   */
  async scan(contract, chain = "solana") {
    const params = new URLSearchParams({ contract, chain });
    return this._request(`/scan?${params}`);
  }

  /**
   * Monitor a wallet for drain threats.
   * @param {Object} opts
   * @param {string} opts.wallet - Wallet address to monitor (0x...)
   * @param {string} opts.callback_url - HTTPS URL to POST alerts to
   * @param {number} [opts.threshold_pct=20] - Balance drop % to trigger alert
   * @param {string} [opts.agent_id] - Agent identifier for grouping
   * @param {string[]} [opts.chains=['ethereum','base']] - Chains to monitor
   * @returns {Promise<Object>}
   */
  async monitor({ wallet, callback_url, threshold_pct = 20, agent_id, chains = ["ethereum", "base"] }) {
    return this._request("/monitor", {
      method: "POST",
      body: JSON.stringify({ wallet, callback_url, threshold_pct, agent_id, chains }),
    });
  }

  /**
   * Emergency freeze all wallets for a wallet address or agent.
   * @param {Object} opts
   * @param {string} [opts.wallet] - Wallet address to freeze
   * @param {string} [opts.agent_id] - Agent ID to freeze all wallets for
   * @param {string} [opts.reason] - Reason for freeze
   * @returns {Promise<Object>}
   */
  async freeze({ wallet, agent_id, reason = "Threat detected" } = {}) {
    const headers = {};
    if (this.apiKey) headers["X-Agent-Key"] = this.apiKey;
    return this._request("/freeze", {
      method: "POST",
      headers,
      body: JSON.stringify({ wallet, agent_id, reason }),
    });
  }

  /**
   * Get recent alerts for a wallet.
   * @param {string} wallet - Wallet address
   * @param {number} [limit=20] - Max alerts to return (max 100)
   * @returns {Promise<Object>}
   */
  async alerts(wallet, limit = 20) {
    const params = new URLSearchParams({ wallet, limit: String(limit) });
    return this._request(`/alerts?${params}`);
  }

  /**
   * Get live protocol statistics.
   * @returns {Promise<Object>}
   */
  async stats() {
    return this._request("/stats");
  }

  /**
   * Safe interaction helper — verify before acting.
   * Returns result if safe, throws if dangerous.
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

  /**
   * Safe scan helper — scan before trading any token.
   * Returns result if safe, throws if dangerous.
   * @param {string} contract
   * @param {string} chain
   */
  async safeScan(contract, chain = "solana") {
    const result = await this.scan(contract, chain);
    if (result.verdict === "DANGEROUS" || result.is_honeypot) {
      throw new Error(`[AgentShield] BLOCKED: ${result.threat_level} — ${JSON.stringify(result.risks || [])}`);
    }
    return result;
  }
}

module.exports = AgentShield;
module.exports.default = AgentShield;
