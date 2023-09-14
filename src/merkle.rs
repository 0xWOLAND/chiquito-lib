use chiquito::{
    frontend::dsl::circuit,
    plonkish::ir::{assignments::AssignmentGenerator, Circuit},
};
use halo2_proofs::arithmetic::Field;
use std::hash::Hash;


struct CircuitParams {}

fn merkle_circuit<F: Field + From<u64> + Hash>() -> (Circuit<F>, Option<AssignmentGenerator<F, ()>>)
{
    use chiquito::frontend::dsl::cb::*;

    let merkle = circuit::<F, (), _>("merkle", |ctx| {});
    todo!()
}
pub fn main() {
    println!("hello ")
}
