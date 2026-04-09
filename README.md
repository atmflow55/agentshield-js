# AgentShield JS SDK

> Trust no contract. Verify before you transact.

Official JavaScript SDK for [AgentShield](https://agentshield.win) — smart contract security for autonomous AI agents. 20 methods covering verification, scanning, wallet monitoring, threat reporting, and leaderboards.

[![npm version](https://img.shields.io/npm/v/agentshield-js)](https://www.npmjs.com/package/agentshield-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Install

```bash
npm install agentshield-js
```

## Quick Start

```javascript
const AgentShield = require('agentshield-js');
const shield = new AgentShield({ apiKey: 'your-key' }); // optional for free tier

// Verify a contract before trading
const result = await shield.verify('0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', 'ethereum');
console.log(result.risk_level);    // "low" | "medium" | "high" | "critical"
console.log(result.is_honeypot);   // false
console.log(result.risks_found);   // []

// Full scan (14+ checks)
const scan = await shield.scan('DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', 'solana');
console.log(scan.mint_authority);  // false
console.log(scan.freeze_authority); // false

// Safe wrapper — throws on dangerous contracts
await shield.safeInteract('0x...', 'base'); // throws if honeypot/rug
```

## All 20 Methods

### Security

| Method | Description |
|--------|-------------|
| `verify(contract, chain)` | Quick safety check — honeypots, rug pulls, taxes, ownership |
| `scan(contract, chain)` | Full 14+ threat scan — mint auth, freeze, proxies, liquidity |
| `deepScan(contract, chain)` | Forensic analysis — bytecode, ownership graph, exploits |
| `verifyBatch(contracts, chain)` | Batch verify up to 50 contracts |
| `contractDiff(contract, chain)` | Detect changes between contract snapshots |
| `safeInteract(contract, chain)` | Verify + throw on danger (use before any tx) |
| `safeScan(contract, chain)` | Scan + throw on danger |

### Wallet Protection

| Method | Description |
|--------|-------------|
| `monitor({ wallet, callback_url })` | Real-time drain detection with auto-freeze |
| `freeze({ wallet, reason })` | Emergency freeze all agent wallets |
| `alerts(wallet, limit)` | Get recent drain alerts |

### Community

| Method | Description |
|--------|-------------|
| `report({ contract, reason, evidence })` | Report malicious contracts (+50 bonus calls) |
| `reputation(agent)` | Get community reputation score |
| `webhook({ contract, callback_url })` | Watch for proxy upgrades, ownership transfers |
| `dashboard()` | Your usage, billing, webhooks |
| `stats()` | Platform-wide statistics |
| `integrations()` | Available integrations |

### Social & Leaderboard

| Method | Description |
|--------|-------------|
| `leaderboard()` | Race to 1M — top 10 win $500 USDC |
| `setAgentName(name)` | Set leaderboard display name |
| `giveaway()` | View active giveaways |
| `giveawayEnter(name)` | Enter giveaway (paid subscribers only) |
| `referral(action, code)` | Create/redeem referral codes (20% commission) |

## Supported Chains

Ethereum, Base, Polygon, Arbitrum, Optimism, BSC, Avalanche, Solana

## Pricing

| Tier | Price | Calls |
|------|-------|-------|
| Free | $0 | 10 verify + 5 scan + 2 deep per day |
| Pay-per-call | $0.001 | Unlimited via x402 (USDC or SOL) |
| Starter | $4.99/mo | 5,000 calls |
| Pro | $19.99/mo | 100,000 + unlimited deep scans |
| Builder | $49.99/mo | Unlimited everything |

## MCP Server

For AI agents using Model Context Protocol:

```bash
npx agentshield-mcp
```

See [agentshield-mcp](https://www.npmjs.com/package/agentshield-mcp) for 19 MCP tools.

## License

MIT
