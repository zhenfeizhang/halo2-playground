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
    // pub(crate) phase_2_column: Column<Advice>,
    // pub(crate) selector: Selector,
    // pub(crate) fixed: Column<Fixed>,
    // pub(crate) instance: Column<Instance>
}

impl TestConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let vanilla_plonk_config = {
            // let selector = meta.complex_selector();

            let phase_1_column = meta.advice_column_in(FirstPhase);
            meta.enable_equality(phase_1_column);
            // // let phase_2_column = meta.advice_column_in(SecondPhase);
            // // meta.enable_equality(phase_2_column);

            // // let fixed = meta.fixed_column();
            // // meta.enable_equality(fixed);

            // // let instance = meta.instance_column();
            // // meta.enable_equality(instance);

            // meta.create_gate("rlc_gate", |meta| {
            //     // phase_2_column | advice | enable_challenge
            //     // ---------------|--------|------------------
            //     // a              | q1     | q2
            //     // b              | 0      | 0
            //     // c              | 0      | 0
            //     // d              | 0      | 0
            //     //
            //     // constraint: q1*(a*b+c-d) = 0
            //     let a = meta.query_advice(phase_1_column, Rotation(0));
            //     let b = meta.query_advice(phase_1_column, Rotation(1));
            //     let c = meta.query_advice(phase_1_column, Rotation(2));
            //     let d = meta.query_advice(phase_1_column, Rotation(3));
            //     let q1 = meta.query_selector(selector);
            //     let cs = q1 * (a.clone() * b + c - d);

            //     vec![cs]
            // });
            VanillaPlonkConfig {
                phase_1_column,
                // phase_2_column,
                // selector,
                // fixed,
                // instance
            }
        };

        // let gate_param = FlexGateConfigParams {
        //     k: 10,
        //     num_advice_per_phase: vec![2],
        //     num_fixed: 1,
        // };

        // let base_field_config = FpConfig::configure(meta, gate_param, &[1], 8);

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
        let halo2_proof_cell = self.halo2_proof_cell(vanilla_plonk_config, layouter);
        println!("halo2 proof cell: {:?}", halo2_proof_cell.value());

        // load the halo2 proof in halo2-lib
        // first create proving and verifying key
        let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(10);
        let mut copy_manager = builder.core().copy_manager.lock().unwrap();
        // let t1 = copy_manager.load_external_assigned(halo2_proof_cell);
        let t1 = {
            let cell = copy_manager.load_external_cell(halo2_proof_cell.cell());
            let mut value = Fr::default();
            halo2_proof_cell.value().map(|f| value = *f);
            AssignedValue {
                value: Assigned::Trivial(value),
                cell: Some(cell),
            }
        };
        drop(copy_manager);

        // let range = builder.range_chip();
        // let chip = FpChip::<Fr, Fr>::new(&range, 88, 3);
        // let gate = chip.gate();
        let chip = GateChip::<Fr>::default();
        let ctx = builder.main(0);

        // let t1 = thread::spawn(move || {
        // let mut copy_manager = builder.core().copy_manager.lock().unwrap();
        // let t1 = copy_manager.load_external_cell(halo2_proof_cell.cell());
        // })
        // .join()
        // .unwrap();

        let c = chip.add(
            ctx,
            QuantumCell::Witness(self.a),
            QuantumCell::Witness(self.b),
        );
        let c2 = ctx.load_witness(self.c);
        ctx.constrain_equal(&c, &c2);
        ctx.constrain_equal(&c, &t1);

        println!("c: {:?}", c);
        println!("c2: {:?}", c2);

        let config_params = builder.calculate_params(Some(20));

        println!("1");
        // MockProver::run(10, &builder, vec![])
        // .unwrap()
        // .assert_satisfied();
        println!("2");
        // let params = ParamsKZG::<Bn256>::setup(10, OsRng);
        // let vk = keygen_vk(&params, &builder).expect("vk should not fail");
        // let pk = keygen_pk(&params, vk, &builder).expect("pk should not fail");

        // let break_points = builder.break_points();

        // let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points.clone());

        Ok(())
    }
}

impl TestCircuit {
    fn halo2_proof_cell(
        &self,
        vanilla_plonk_config: VanillaPlonkConfig,
        mut layouter: impl Layouter<Fr>,
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
                        || Value::known(self.a),
                    )
                    // let offset = 0;
                    // vanilla_plonk_config
                    //     .selector
                    //     .enable(&mut region, offset)
                    //     .unwrap();
                    // let a = region
                    //     .assign_advice(
                    //         || "a",
                    //         vanilla_plonk_config.phase_1_column,
                    //         offset,
                    //         || Value::known(self.a),
                    //     )
                    //     .unwrap();
                    // region
                    //     .assign_advice(
                    //         || "one",
                    //         vanilla_plonk_config.phase_1_column,
                    //         offset + 1,
                    //         || Value::known(Fr::one()),
                    //     )
                    //     .unwrap();
                    // let b = region
                    //     .assign_advice(
                    //         || "b",
                    //         vanilla_plonk_config.phase_1_column,
                    //         offset + 2,
                    //         || Value::known(self.b),
                    //     )
                    //     .unwrap();
                    // let c = region
                    //     .assign_advice(
                    //         || "c",
                    //         vanilla_plonk_config.phase_1_column,
                    //         offset + 3,
                    //         || Value::known(self.c),
                    //     )
                    //     .unwrap();
                    // Ok(a)
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

        println!("1");

        // MockProver::run(10, &builder, vec![])
        //     // .unwrap()
        //     // .assert_satisfied();
        //     ;
        println!("2");
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
