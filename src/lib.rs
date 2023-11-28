use std::cell::RefCell;

use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
        GateChip,
    },
    halo2_proofs::{
        self,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    },
};
use halo2_proofs::halo2curves;
use halo2curves::bn256::Fr;

const K: usize = 6;

#[derive(Clone)]
pub struct TestConfig {
    // halo2-lib config
    pub base_circuit_config: BaseConfig<Fr>,
}

impl TestConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let base_circuit_param = BaseCircuitParams {
            k: K,
            // num_advice_per_phase: vec![1, 1],
            num_advice_per_phase: vec![1],
            num_fixed: 1,
            // num_lookup_advice_per_phase: vec![1,1],
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: Some(2),
            num_instance_columns: 0,
        };
        let base_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_param);

        Self {
            base_circuit_config,
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

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let mut base_circuit_builder = self.base_circuit_builder.borrow_mut();

        // compute c with halo2-lib's first phase gate
        let ctx = base_circuit_builder.main(0);

        let c2 = ctx.load_witness(self.c);
        let c3 = ctx.load_witness(self.c);
        ctx.constrain_equal(&c2, &c3);

        base_circuit_builder.synthesize(config.base_circuit_config, layouter)?;
        base_circuit_builder.clear();
        println!("finished");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_base::{
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::Bn256,
            plonk::{keygen_pk, keygen_vk},
            poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
        },
        utils::testing::{check_proof, gen_proof},
    };

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
        let prover = MockProver::<Fr>::run(K as u32, &circuit, vec![]).unwrap();
        println!("finished mock proving");
        prover.assert_satisfied();
        println!("finished mock run, prover satisfied\n\n");

        let params = ParamsKZG::<Bn256>::new(K as u32);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
        let proof = gen_proof(&params, &pk, circuit);
        check_proof(&params, &vk, &proof, true);
    }
}
