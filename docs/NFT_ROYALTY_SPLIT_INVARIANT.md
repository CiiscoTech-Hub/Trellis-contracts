# NFT Royalty Split Invariant Enforcement Across Secondary Sales (#522)

## Overview

The NFT Royalty Split Invariant module (`shared::nft_royalty`) guarantees fair, deterministic, and conservation-safe royalty distribution across all secondary marketplace trades on Trellis:

1. **Exact Balance Conservation Invariant**:
   - The gross sale price paid by the buyer must equal the exact sum of all disbursements:
     $$\text{gross\_sale\_price} \equiv \text{platform\_fee} + \sum_{i=1}^M \text{royalty\_amount}_i + \text{seller\_net\_proceeds}$$
   - Checked and enforced to the exact integer stroop for every secondary sale before token transfers are executed.

2. **Multi-Recipient Split Distribution**:
   - Creators and project foundations can register up to 10 distinct royalty recipients with configurable basis-point shares (`share_bps`).
   - The sum of all shares must not exceed `MAX_ROYALTY_BPS` (1,000 bps = 10%).
   - Duplicate recipient addresses are rejected at configuration time.

3. **Deterministic Truncation Residue Handling**:
   - In integer arithmetic with basis-point calculations, divisions can produce integer truncation remainders:
     $$\Delta = \left\lfloor \frac{\text{price} \times \text{total\_bps}}{10,000} \right\rfloor - \sum_{i} \left\lfloor \frac{\text{price} \times \text{share\_bps}_i}{10,000} \right\rfloor$$
   - The module deterministically accounts for any residue by crediting it to seller proceeds, ensuring zero token inflation and zero token loss across any odd price magnitude.

---

## Invariant Verification Workflow

```text
Secondary NFT Sale (price, fee_bps)
          │
          ▼
[ Recipient Config Check ] ── (duplicates? > 1000 bps?) ──► Fail: (InvalidRoyaltyBps/DuplicateRecipient)
          │ Pass
          ▼
[ Compute Platform Fee ] ── (price * fee_bps / 10,000)
          │
          ▼
[ Compute Recipient Payouts ] ── (price * share_bps_i / 10,000)
          │
          ▼
[ Deduct Seller Proceeds ] ── (price - fee - total_royalties)
          │ (proceeds < 0?) ──► Fail: SellerProceedsNegative (2056)
          ▼
[ Invariant Check ] ── (fee + royalties + proceeds == price?)
          │ Fail
          ├────────────────────────────────────────► Fail: ConservationInvariantViolated (2054)
          │ Pass
          ▼
Execute Atomic Token Transfers
```

---

## Operational Paths

### 1. Normal Path
- Buyer purchases a listed NFT or accepts an auction hammer price.
- Invariant verifier computes `RoyaltyExecutionPlan` for secondary trade.
- Exact payouts are computed for each creator and seller proceeds are transferred atomically.

### 2. Failure Path
- **Invalid Rate**: Config with recipient shares exceeding 1,000 bps fails with `NftRoyaltyError::RoyaltyExceedsCap` or `InvalidRoyaltyBps`.
- **Negative Proceeds**: If fee + royalty exceeds price, fails with `NftRoyaltyError::SellerProceedsNegative`.
- **Conservation Breakdown**: If arithmetic balance fails to match price, transaction fails with `NftRoyaltyError::ConservationInvariantViolated`.

### 3. Edge Cases & Rounding Integrity
- **Odd / Micro Prices**: For small purchases (e.g. 7 stroops) where individual fractional splits truncate to 0, token conservation still holds with 100% precision without creating orphan balances.
- **Zero Royalties**: For collections without royalty recipients or on primary mint sales, total royalty is 0 and net proceeds equal `price - platform_fee`.

---

## Error Taxonomy

| Code | Variant | Description | Remediation |
|---|---|---|---|
| `2050` | `InvalidSalePrice` | Sale price is zero or negative | Provide positive sale price |
| `2051` | `InvalidFeeRate` | Platform fee bps exceeds 1,000 (10%) | Configure fee within 0–1,000 bps range |
| `2052` | `InvalidRoyaltyBps` | Share bps is negative or exceeds collection cap | Provide valid recipient basis points |
| `2053` | `RoyaltyExceedsCap` | Sum of recipient shares exceeds 1,000 bps | Ensure total collection royalties <= 10% |
| `2054` | `ConservationInvariantViolated` | Exact sum of payouts does not equal gross sale price | Internal arithmetic invariant check failure |
| `2055` | `DuplicateRoyaltyRecipient` | Recipient address listed multiple times | Ensure all recipient addresses are unique |
| `2056` | `SellerProceedsNegative` | Deductions exceed total sale price | Check platform fee and royalty configuration |
| `2057` | `MaxRecipientsExceeded` | More than 10 royalty recipients supplied | Limit recipient count to maximum 10 |
