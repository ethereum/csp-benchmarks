use spartan_whir::{WhirFoldingSchedule, WhirParams};

pub(crate) fn for_dimensions(witness_log: usize, outer_log: usize) -> WhirParams {
    match (witness_log, outer_log) {
        (9, 9) => WhirParams {
            pow_bits: 0,
            folding_factor: 3,
            starting_log_inv_rate: 4,
            rs_domain_initial_reduction_factor: 1,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 3,
                rest: 1,
            }),
            round_log_inv_rates: vec![],
        },
        (10, 10) => WhirParams {
            pow_bits: 1,
            folding_factor: 4,
            starting_log_inv_rate: 4,
            rs_domain_initial_reduction_factor: 1,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 4,
                rest: 1,
            }),
            round_log_inv_rates: vec![],
        },
        (16, 16) => WhirParams {
            pow_bits: 1,
            folding_factor: 6,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 3,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 6,
                rest: 4,
            }),
            round_log_inv_rates: vec![],
        },
        (17, 17) => WhirParams {
            pow_bits: 1,
            folding_factor: 7,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 4,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 7,
                rest: 4,
            }),
            round_log_inv_rates: vec![],
        },
        (18, 18) => WhirParams {
            pow_bits: 1,
            folding_factor: 8,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 5,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 8,
                rest: 4,
            }),
            round_log_inv_rates: vec![],
        },
        (19, 19) => WhirParams {
            pow_bits: 4,
            folding_factor: 8,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 7,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 8,
                rest: 5,
            }),
            round_log_inv_rates: vec![4],
        },
        (20, 20) => WhirParams {
            pow_bits: 4,
            folding_factor: 8,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 6,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 8,
                rest: 6,
            }),
            round_log_inv_rates: vec![4],
        },
        (21, 21) => WhirParams {
            pow_bits: 4,
            folding_factor: 8,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 7,
            folding_schedule: Some(WhirFoldingSchedule::ConstantFromSecondRound {
                first: 8,
                rest: 4,
            }),
            round_log_inv_rates: vec![],
        },
        _ => panic!(
            "no measured WHIR parameters for witness dimension {witness_log} and outer dimension {outer_log}"
        ),
    }
}
