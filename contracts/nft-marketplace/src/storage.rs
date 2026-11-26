use soroban_sdk::{contracttype, Address, Env};

use shared::storage::{persistent_get, persistent_set};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    PendingRefund(Address, Address),
    CollectionInfo(Address),
    AuctionConfig(Address, u64),
    Auction(Address, u64),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuctionConfig {
    pub min_bid_increment_bps: u32,
    pub anti_snipe_window: u64,
    pub anti_snipe_extension: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auction {
    pub seller: Address,
    pub token: Address,
    pub highest_bid: i128,
    pub highest_bidder: Option<Address>,
    pub end_time: u64,
}

pub const MIN_BID_INCREMENT_BPS_FLOOR: u32 = 100;
pub const MAX_ANTI_SNIPE_EXTENSION: u64 = 3600;

pub fn validate_auction_config(config: &AuctionConfig) -> bool {
    config.min_bid_increment_bps >= MIN_BID_INCREMENT_BPS_FLOOR
        && config.min_bid_increment_bps <= 10_000
        && config.anti_snipe_extension <= MAX_ANTI_SNIPE_EXTENSION
        && config.anti_snipe_window <= config.anti_snipe_extension.saturating_mul(10)
}

pub fn apply_anti_snipe(auction: &mut Auction, config: &AuctionConfig, now: u64) -> bool {
    if auction.end_time.saturating_sub(now) <= config.anti_snipe_window && config.anti_snipe_extension > 0 {
        auction.end_time = now.saturating_add(config.anti_snipe_extension);
        true
    } else {
        false
    }
}

pub fn min_next_bid(auction: &Auction, config: &AuctionConfig) -> Option<i128> {
    if auction.highest_bid == 0 {
        return Some(1);
    }
    let increment = auction
        .highest_bid
        .checked_mul(config.min_bid_increment_bps as i128)?
        .checked_div(10_000)?;
    let increment = if increment == 0 { 1 } else { increment };
    auction.highest_bid.checked_add(increment)
}

pub struct PendingRefunds;

impl PendingRefunds {
    pub fn get(env: &Env, bidder: &Address, token: &Address) -> i128 {
        persistent_get(env, &DataKey::PendingRefund(bidder.clone(), token.clone())).unwrap_or(0)
    }

    pub fn add(env: &Env, bidder: &Address, token: &Address, amount: i128) -> Result<i128, crate::MarketError> {
        let current = Self::get(env, bidder, token);
        let new_total = current.checked_add(amount).ok_or(crate::MarketError::Overflow)?;
        persistent_set(env, &DataKey::PendingRefund(bidder.clone(), token.clone()), &new_total);
        Ok(new_total)
    }

    pub fn clear(env: &Env, bidder: &Address, token: &Address) {
        persistent_set(env, &DataKey::PendingRefund(bidder.clone(), token.clone()), &0i128);
    }
}

pub struct AuctionStore;

impl AuctionStore {
    pub fn get_config(env: &Env, collection: &Address, auction_id: u64) -> Option<AuctionConfig> {
        persistent_get(env, &DataKey::AuctionConfig(collection.clone(), auction_id))
    }

    pub fn set_config(env: &Env, collection: &Address, auction_id: u64, config: &AuctionConfig) {
        persistent_set(env, &DataKey::AuctionConfig(collection.clone(), auction_id), config);
    }

    pub fn get(env: &Env, collection: &Address, auction_id: u64) -> Option<Auction> {
        persistent_get(env, &DataKey::Auction(collection.clone(), auction_id))
    }

    pub fn set(env: &Env, collection: &Address, auction_id: u64, auction: &Auction) {
        persistent_set(env, &DataKey::Auction(collection.clone(), auction_id), auction);
    }

    pub fn remove(env: &Env, collection: &Address, auction_id: u64) {
        env.storage()
            .persistent()
            .remove(&DataKey::Auction(collection.clone(), auction_id));
    }
}
