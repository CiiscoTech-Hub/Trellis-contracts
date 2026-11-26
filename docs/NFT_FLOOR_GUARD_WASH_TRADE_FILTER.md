# NFT Collection Floor Price Guard and Wash-Trade Filter (#543)

## Overview

The NFT Collection Floor Price Guard and Wash-Trade Filter module (`shared::nft_guard`) provides real-time market integrity mechanisms for the Trellis Soroban NFT ecosystem:

1. **Floor Price Guard**:
   - Enforces an absolute minimum allowable floor price per collection (`min_floor_price`).
   - Limits steep, manipulative floor price crashes via basis-point deviation bounds (`max_floor_drop_bps`).
   - Evaluates trades against smoothed Time-Weighted Average Price (TWAP) baselines to prevent flash-crash manipulation.
2. **Wash-Trade Detection & Filter**:
   - **Direct Self-Dealing**: Instantly rejects any trade where `buyer == seller`.
   - **Circular / Churn Cycles**: Tracks an $O(1)$-bounded ring buffer of past token owners ($K \le 8$) and blocks recycled wash trading within minimum holding duration windows (`min_holding_period_ledgers`).
   - **Clean History Maintenance**: Records verified trades into the bounded history buffer without unbounded storage growth.

## Architecture & Data Model

```text
Trade Submission
       │
       ▼
[ Self-Dealing Check ] ── (buyer == seller) ──────────────► Reject (MarketGuardError::SelfDealing)
       │ Pass
       ▼
[ Circular History Check ] ── (recent buyer re-purchase) ──► Reject (MarketGuardError::WashTradeCycle)
       │ Pass
       ▼
[ Holding Window Check ] ── (seller holding < min) ──────► Reject (MarketGuardError::RapidChurn)
       │ Pass
       ▼
[ Floor Deviation Check ] ── (price drop > max_drop_bps) ─► Reject (MarketGuardError::FloorDropExceeded)
       │ Pass
       ▼
[ Commit Clean Trade ] ──► Update Floor TWAP & Append Ring Buffer (O(1))
```

## Algorithmic Complexity

| Component | Time Complexity | Space Complexity |
|---|---|---|
| Floor Price Verification | $O(1)$ arithmetic | $O(1)$ config/state struct |
| Wash-Trade Filter | $O(K)$ where $K \le 8$ (bounded ring) | $O(1)$ bounded buffer |
| Clean Trade Commit | $O(1)$ circular ring push | $O(1)$ persistent storage |

## Edge Cases and Recovery

- **Rapid Volume Surge**: Ring buffer eviction drops the oldest historical entry when capacity is reached, preventing unbounded ledger footprints.
- **Circuit Breaker / Market Crash**: If an intentional market correction exceeds `max_floor_drop_bps`, an admin with appropriate permissions can update `FloorPriceGuardConfig` or trigger phased floor step-downs.
- **Rollback Behavior**: If any check fails, no storage mutation occurs and the transaction rolls back cleanly.
