use std::{marker::PhantomData, sync::Arc, thread};

use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        flex_gate::{FlexGateConfig, FlexGateConfigParams},
        GateChip, RangeChip,
    },
    gates::{
        circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
        GateInstructions,
    },
    halo2_proofs::{
        self,
        circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Bn256,
        plonk::{
            keygen_pk, keygen_vk, Advice, Assigned, Circuit, Column, ConstraintSystem, Error,
            FirstPhase, Fixed, Instance, SecondPhase, Selector,
        },
        poly::{kzg::commitment::ParamsKZG, Rotation},
    },
    virtual_region::copy_constraints::{CopyConstraintManager, SharedCopyConstraintManager},
    AssignedValue, Context, QuantumCell,
};
use halo2_ecc::fields::{
    fp::{FpChip, FpConfig},
    FieldChip,
};
use halo2_proofs::halo2curves;
use halo2curves::bn256::{Fq, Fr};
use rand_core::OsRng;

#[derive(Clone)]
pub struct TestConfig {
    pub base_circuit_builder: BaseConfig<Fr>,
    pub vanilla_plonk_config: VanillaPlonkConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct VanillaPlonkConfig {
    pub(crate) phase_1_column: Column<Advice>,
}

impl TestConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let vanilla_plonk_config = {
            let phase_1_column = meta.advice_column_in(FirstPhase);
            meta.enable_equality(phase_1_column);

            VanillaPlonkConfig { phase_1_column }
        };

        let base_circuit_param = BaseCircuitParams {
            k: 10,
            num_advice_per_phase: vec![1],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: None,
            num_instance_columns: 1,
        };
        let base_circuit_builder =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_param);

        Self {
            base_circuit_builder,
            vanilla_plonk_config,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestCircuit {
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
}

impl Circuit<Fr> for TestCircuit {
    type Config = TestConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        Self::Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let Self::Config {
            base_circuit_builder,
            vanilla_plonk_config,
        } = config;

        // assign a cell in halo2 proof
        let halo2_proof_cell_2 = self.halo2_proof_cell(vanilla_plonk_config, &mut layouter, 2);
        let halo2_proof_cell_3 = self.halo2_proof_cell(vanilla_plonk_config, &mut layouter, 3);
        println!("halo2 proof cell: {:?}", halo2_proof_cell_2.value());
        println!("halo2 proof cell: {:?}", halo2_proof_cell_3.value());

        // load the halo2 proof in halo2-lib
        // first create proving and verifying key
        let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(10);
        let mut copy_manager = builder.core().copy_manager.lock().unwrap();

        // t1 == 2
        let t1 = {
            let cell = copy_manager.load_external_cell(halo2_proof_cell_2.cell());
            let mut value = Fr::default();
            halo2_proof_cell_2.value().map(|f| value = *f);
            AssignedValue {
                value: Assigned::Trivial(value),
                cell: Some(cell),
            }
        };
        // t2 == 3
        let t2 = {
            let cell = copy_manager.load_external_cell(halo2_proof_cell_3.cell());
            let mut value = Fr::default();
            halo2_proof_cell_3.value().map(|f| value = *f);
            AssignedValue {
                value: Assigned::Trivial(value),
                cell: Some(cell),
            }
        };
        drop(copy_manager);

        let chip = GateChip::<Fr>::default();
        let ctx = builder.main(0);

        let c = chip.add(
            ctx,
            QuantumCell::Witness(self.a),
            QuantumCell::Witness(self.b),
        );
        let c2 = ctx.load_witness(self.c);
        ctx.constrain_equal(&c, &c2);

        // c == 3; t1 == 2; t2 == 3;
        // so the following constraints should fail
        ctx.constrain_equal(&c, &t1);
        ctx.constrain_equal(&c, &t2);

        println!("c: {:?}", c);
        println!("c2: {:?}", c2);
        println!("t1: {:?}", t1);
        println!("t2: {:?}", t2);

        let config_params = builder.calculate_params(Some(20));

        Ok(())
    }
}

impl TestCircuit {
    fn halo2_proof_cell(
        &self,
        vanilla_plonk_config: VanillaPlonkConfig,
        layouter: &mut impl Layouter<Fr>,
        value: u64,
    ) -> AssignedCell<Fr, Fr> {
        // assign a cell in halo2 proof
        layouter
            .assign_region(
                || "halo2-proof",
                |mut region| -> Result<AssignedCell<Fr, Fr>, Error> {
                    region.assign_advice(
                        || "a",
                        vanilla_plonk_config.phase_1_column,
                        0,
                        || Value::known(Fr::from(value)),
                    )
                },
            )
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::halo2_proofs::dev::MockProver;

    use super::*;
    #[test]
    fn test_circuit() {
        let circuit = TestCircuit {
            a: Fr::from(1),
            b: Fr::from(2),
            c: Fr::from(3),
        };

        // load the halo2 proof in halo2-lib
        let (builder, config_params) = {
            let mut builder =
                RangeCircuitBuilder::<Fr>::from_stage(CircuitBuilderStage::Keygen).use_k(10); //.use_lookup_bits(8);

            let chip = GateChip::<Fr>::default();
            let ctx = builder.main(0);

            let c = chip.add(
                ctx,
                QuantumCell::Witness(Fr::from(1)),
                QuantumCell::Witness(Fr::from(2)),
            );
            let c2 = ctx.load_witness(Fr::from(3));
            ctx.constrain_equal(&c, &c2);

            let config_params = builder.calculate_params(Some(20));
            (builder, config_params)
        };

        let params = ParamsKZG::<Bn256>::setup(10, OsRng);
        let vk = keygen_vk(&params, &builder).expect("vk should not fail");
        let pk = keygen_pk(&params, vk, &builder).expect("pk should not fail");

        let break_points = builder.break_points();

        let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points.clone());

        let ctx = builder.main(0);
        let chip = GateChip::<Fr>::default();
        let c = chip.add(
            ctx,
            QuantumCell::Witness(Fr::from(3)),
            QuantumCell::Witness(Fr::from(4)),
        );
        let c2 = ctx.load_witness(Fr::from(7));
        ctx.constrain_equal(&c, &c2);

        MockProver::run(10, &builder, vec![])
            .unwrap()
            .assert_satisfied();
        let prover = MockProver::run(11, &circuit, vec![vec![Fr::one()]]).unwrap();
        // let prover = MockProver::run(11, &circuit, vec![]).unwrap();
        // println!("here");
        prover.assert_satisfied();
    }
}
