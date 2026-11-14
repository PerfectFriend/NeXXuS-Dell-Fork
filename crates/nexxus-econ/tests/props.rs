//! E3: property-тесты экономики (anti-loop, saturating math, vesting, degradation).
//! proptest: случайные u64/i64 входы не должны паниковать, оборачиваться или
//! нарушать инварианты спецификации.

use nexxus_core::types::Money;
use nexxus_econ::degradation::{health_from_offline, reset_downtime_penalty, Health};
use nexxus_econ::sections::{
    anti_loop_invariant_holds, daily_storer_reward, daily_subscription_cost, self_dealing_yield_per_gb,
    split_into_sections,
};
use nexxus_econ::vesting::VestingSchedule;
use nexxus_econ::{
    DAILY_NEXX_RATE_PER_GB, DEGRADED_AFTER_DAYS, FREEZE_REWARDS_AFTER_HOURS, SECTION_SIZE_GB,
    SUBSCRIPTION_DAILY_COST_PER_GB, VESTING_LOCK_DAYS, WARNING_AFTER_DAYS,
};
use proptest::prelude::*;

proptest! {
    /// Anti-loop: fee writer строго больше reward storer — для любых констант。
    #[test]
    fn anti_loop_invariant_always_holds(_seed in any::<u64>()) {
        prop_assert!(anti_loop_invariant_holds());
        prop_assert!(SUBSCRIPTION_DAILY_COST_PER_GB > DAILY_NEXX_RATE_PER_GB);
        prop_assert!(self_dealing_yield_per_gb().0 < 0, "self-dealing строго отрицателен");
    }

    /// Saturating math: reward/cost никогда не паникуют и не уходят в минус,
    /// монотонны по gb, и для малых gb точны (rate * gb без округления).
    #[test]
    fn money_math_saturates_and_is_monotone(gb in any::<u64>(), gb2 in any::<u64>()) {
        let r = daily_storer_reward(gb);
        let c = daily_subscription_cost(gb);
        prop_assert!(r.0 >= 0);
        prop_assert!(c.0 >= 0);
        if gb <= (i64::MAX as u64) / DAILY_NEXX_RATE_PER_GB.unsigned_abs() {
            prop_assert_eq!(r.0, DAILY_NEXX_RATE_PER_GB.saturating_mul(gb as i64));
        }
        if gb <= gb2 {
            prop_assert!(daily_storer_reward(gb).0 <= daily_storer_reward(gb2).0);
            prop_assert!(daily_subscription_cost(gb).0 <= daily_subscription_cost(gb2).0);
        }
        // u64::MAX обязан сатурировать, не wrap
        prop_assert_eq!(daily_storer_reward(u64::MAX).0, i64::MAX);
        prop_assert_eq!(daily_subscription_cost(u64::MAX).0, i64::MAX);
    }

    /// Conservation: sections*16 + remainder == free_gb для любого входа.
    #[test]
    fn section_split_conserves_gb(free_gb in any::<u64>()) {
        let s = split_into_sections(free_gb);
        prop_assert_eq!(
            s.sections_16gb.saturating_mul(SECTION_SIZE_GB).saturating_add(s.remainder_gb),
            free_gb,
            "разбиение обязано сохранять суммарные GB"
        );
        prop_assert!(s.remainder_gb < SECTION_SIZE_GB || free_gb == u64::MAX && s.remainder_gb == SECTION_SIZE_GB - 1);
        // vault quota монотонна по free_gb
        let s2 = split_into_sections(free_gb.saturating_add(1));
        prop_assert!(s.vault_quota_gb <= s2.vault_quota_gb.saturating_add(1));
    }

    /// Vesting: vested монотонно растёт с днями, никогда не превышает total,
    /// vested + unvested + burned == total (conservation), после LOCK — полностью.
    #[test]
    fn vesting_conserves_and_monotone(total in 0..=i64::MAX, days in 0..VESTING_LOCK_DAYS * 2, days2 in 0..VESTING_LOCK_DAYS * 2) {
        let mut s = VestingSchedule::new(Money(total));
        s.advance(days);
        let v = s.vested().0;
        prop_assert!(v >= 0);
        prop_assert!(v <= total, "vested не может превысить total");
        prop_assert!(s.unvested().0 >= 0);
        prop_assert_eq!(v + s.unvested().0, total, "conservation до burn");
        if days >= VESTING_LOCK_DAYS {
            prop_assert_eq!(v, total, "после LOCK всё vested");
            prop_assert!(s.is_fully_vested());
        }
        let v1 = s.vested().0;
        s.advance(days2);
        prop_assert!(s.vested().0 >= v1, "vested монотонно не убывает");
        // burn: vested не тронут, conservation сохраняется
        let before = s.vested().0;
        let unvested_before = s.unvested().0;
        let burned = s.burn_unvested().0;
        prop_assert_eq!(burned, unvested_before, "burn сжигает ровно unvested");
        prop_assert_eq!(s.vested().0, before, "burn не трогает vested");
        prop_assert_eq!(s.unvested().0, 0);
        prop_assert_eq!(s.vested().0 + burned, total);
    }

    /// Degradation ladder: монотонно хуже по offline_hours, пороги точные,
    /// u64::MAX не паникует.
    #[test]
    fn degradation_ladder_monotone(h1 in any::<u64>(), h2 in any::<u64>()) {
        fn rank(h: Health) -> u8 {
            match h {
                Health::Online => 0,
                Health::RewardsFrozen => 1,
                Health::Warning14d => 2,
                Health::Degraded28d => 3,
            }
        }
        let a = health_from_offline(h1);
        let b = health_from_offline(h2);
        if h1 <= h2 {
            prop_assert!(rank(a) <= rank(b), "больше offline — не лучше health");
        }
        // точные пороги
        prop_assert_eq!(health_from_offline(0), Health::Online);
        prop_assert_eq!(health_from_offline(FREEZE_REWARDS_AFTER_HOURS - 1), Health::Online);
        prop_assert_eq!(health_from_offline(FREEZE_REWARDS_AFTER_HOURS), Health::RewardsFrozen);
        prop_assert_eq!(health_from_offline(WARNING_AFTER_DAYS * 24 - 1), Health::RewardsFrozen);
        prop_assert_eq!(health_from_offline(WARNING_AFTER_DAYS * 24), Health::Warning14d);
        prop_assert_eq!(health_from_offline(DEGRADED_AFTER_DAYS * 24), Health::Degraded28d);
        let _ = health_from_offline(u64::MAX); // no panic
        prop_assert!(Health::Degraded28d.burns_unvested());
        prop_assert!(Health::Warning14d.needs_emergency_replication());
        prop_assert!(!Health::RewardsFrozen.burns_unvested());
    }

    /// PoR reset: только после порога раундов.
    #[test]
    fn por_reset_threshold(rounds in any::<u8>()) {
        prop_assert_eq!(reset_downtime_penalty(rounds), rounds >= 3);
    }
}
