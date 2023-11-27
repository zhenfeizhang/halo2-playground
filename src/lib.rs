use std::cell::RefCell;

use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        GateChip, GateInstructions,
    },
    halo2_proofs::{
        self,
        circuit::{Layouter, Region, SimpleFloorPlanner, Value},
        plonk::{Advice, Assigned, Circuit, Column, ConstraintSystem, Error, FirstPhase},
    },
    AssignedValue,
};
use halo2_proofs::halo2curves;
use halo2curves::bn256::Fr;

const K: usize = 7;

#[derive(Clone)]
pub struct TestConfig {
    // halo2-lib config
    pub base_circuit_config: BaseConfig<Fr>,
    // halo2 proof config
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
            k: K,
            num_advice_per_phase: vec![1, 1],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![],
            lookup_bits: None,
            num_instance_columns: 0,
        };
        let base_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_param);

        Self {
            base_circuit_config,
            vanilla_plonk_config,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TestCircuit {
    // circuit builder for halo2-lib
    pub base_circuit_builder: RefCell<BaseCircuitBuilder<Fr>>,
    // chip used for halo2-lib
    pub gate_chip: GateChip<Fr>,
    // circuit witnesses
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
        // assign a halo2 proof cell
        let halo2_proof_cell = layouter.assign_region(
            || "halo2 proof",
            |mut region| {
                region.assign_advice(
                    || "2",
                    config.vanilla_plonk_config.phase_1_column,
                    0,
                    || Value::known(self.c),
                )
            },
        )?;

        // load the cell to halo2-lib
        let mut base_circuit_builder = self.base_circuit_builder.borrow_mut();
        let mut copy_manager = base_circuit_builder.core().copy_manager.lock().unwrap();
        let mut value = Fr::default();
        halo2_proof_cell.value().map(|f| value = *f);
        let halo2_lib_cell = AssignedValue {
            value: Assigned::Trivial(value),
            cell: Some(copy_manager.load_external_cell(halo2_proof_cell.cell())),
        };
        println!("copy manager before dropped: {:?}", copy_manager);
        drop(copy_manager);
        println!("dropped");

        println!("\n\nphase 1");
        // compute c with halo2-lib's first phase gate
        let (a, b) = {
            let ctx = base_circuit_builder.main(0);

            let a = ctx.load_witness(self.a);
            let b = ctx.load_witness(self.b);
            let c = self.gate_chip.add(ctx, a, b);

            let c2 = ctx.load_witness(self.c);
            ctx.constrain_equal(&halo2_lib_cell, &c2);
            ctx.constrain_equal(&halo2_lib_cell, &c);
            base_circuit_builder.synthesize_ref_layouter_phase_0(
                config.base_circuit_config.clone(),
                &mut layouter,
            )?;
            (a, b)
        };

        println!("\n\nphase 2");
        // compute c with halo2-lib's second phase gate
        {
            let ctx = base_circuit_builder.main(1);
            let c3 = self.gate_chip.add(ctx, a, b);

            println!("a: {:?}", a.cell);
            println!("b: {:?}", b.cell);
            println!("c3: {:?}", c3.cell);

            ctx.constrain_equal(&halo2_lib_cell, &c3);
            base_circuit_builder.synthesize_ref_layouter_phase_1(
                config.base_circuit_config.clone(),
                &mut layouter,
            )?;
        }
        println!("config: {:?}", config.base_circuit_config);
        // println!("layouter: {:?}", layouter.namespace(||"base phase 1 + constants assignments + copy constraints" ));
        // println!("layouter: {:?}", layouter.get_root());
        println!("finished");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        halo2_proofs::{
            dev::MockProver,
            halo2curves::{
                bn256::Bn256,
                ff::{FromUniformBytes, WithSmallOrderMulGroup},
            },
            plonk::{keygen_pk, keygen_vk, ProvingKey},
            poly::{
                commitment::{CommitmentScheme, ParamsProver},
                kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
            },
            transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
        },
        utils::testing::{check_proof_with_instances, gen_proof},
    };
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn test_circuit() {
        let base_circuit_builder = BaseCircuitBuilder::new(false);

        let circuit = TestCircuit {
            base_circuit_builder: RefCell::new(base_circuit_builder),
            gate_chip: GateChip::new(),
            a: Fr::from(1),
            b: Fr::from(2),
            c: Fr::from(3),
        };
        let prover = MockProver::<Fr>::run(4, &circuit, vec![]).unwrap();
        println!("finished mock run");
        prover.assert_satisfied();
        // let params = ParamsKZG::<Bn256>::new(K as u32);

        // let vk = keygen_vk(&params, &circuit).unwrap();
        // let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();

        // // let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // let proof = gen_proof(&params, &pk, circuit);

        // check_proof_with_instances(&params, &vk, &proof, &[], true);
    }
}
