use chiquito::ast::{query::Queriable, Expr};
use chiquito::frontend::dsl::{super_circuit, CircuitContext};
use chiquito::plonkish::backend::halo2::{chiquitoSuperCircuit2Halo2, ChiquitoHalo2SuperCircuit};
use chiquito::plonkish::compiler::cell_manager::SingleRowCellManager;
use chiquito::plonkish::compiler::config;
use chiquito::plonkish::compiler::step_selector::SimpleStepSelectorBuilder;
use chiquito::plonkish::ir::sc::SuperCircuit;
use halo2_proofs::dev::MockProver;
use halo2curves::bn256::Fr;
use halo2curves::ff::{Field, PrimeField};
use std::hash::Hash;

pub fn mux1<F: PrimeField>(a: Queriable<F>, b: Queriable<F>, s: Queriable<F>) -> Expr<F> {
    (a - b) * s + b
}

pub fn simple_hash<F: PrimeField>(a: Queriable<F>, b: Queriable<F>) -> Expr<F> {
    (a * Expr::from(931_u32)) + (b * Expr::from(2358_u32))
}

#[derive(Clone)]
struct RoundValues<F: PrimeField> {
    pub leaf: F,
    pub root: F,
    pub path_index: F,
    pub sibling: F,
    pub hash: F,
}

#[derive(Clone)]
struct Inputs<F: PrimeField + Eq + Hash> {
    pub leaf: F,
    pub root: F,
    pub path_indices: Vec<F>,
    pub siblings: Vec<F>,
}

fn merkle_circuit<F>(ctx: &mut CircuitContext<F, Inputs<F>>, n_levels: usize)
where
    F: PrimeField + From<u64> + Hash,
{
    use chiquito::frontend::dsl::cb::*;

    let path_index = ctx.forward("path_index");
    let sibling = ctx.forward("sibling");
    let hash = ctx.forward("hash");
    let root = ctx.forward("root");
    let leaf = ctx.forward("leaf");

    let merkle_first_step = ctx.step_type_def("merkle first step", |ctx| {
        let mux: Vec<Queriable<F>> = (0..2)
            .map(|i| ctx.internal(format!("mux_{:?}", i).as_str()))
            .collect();
        ctx.setup(move |ctx| {
            ctx.transition(eq(path_index * (-path_index + 1), 0));
            ctx.constr(eq(mux[0], mux1(hash, sibling, path_index)));
            ctx.constr(eq(mux[1], mux1(sibling, hash, path_index)));
            ctx.constr(eq(hash.next(), simple_hash(mux[0], mux[1])));
        });

        ctx.wg(move |ctx, round_values: RoundValues<F>| {
            ctx.assign(leaf, round_values.leaf);
            ctx.assign(root, round_values.root);
            ctx.assign(path_index, round_values.path_index);
            ctx.assign(sibling, round_values.sibling);
            ctx.assign(hash, round_values.hash);
        })
    });

    let merkle_step = ctx.step_type_def("merkle step", |ctx| {
        let mux: Vec<Queriable<F>> = (0..2)
            .map(|i| ctx.internal(format!("mux_{:?}", i).as_str()))
            .collect();
        ctx.setup(move |ctx| {
            ctx.transition(eq(path_index * (-path_index + 1), 0));
            ctx.constr(eq(mux[0], mux1(hash, sibling, path_index)));
            ctx.constr(eq(mux[1], mux1(sibling, hash, path_index)));
            ctx.constr(eq(hash.next(), simple_hash(mux[0], mux[1])));
        });

        ctx.wg(move |ctx, round_values: RoundValues<F>| {
            ctx.assign(leaf, round_values.leaf);
            ctx.assign(root, round_values.root);
            ctx.assign(path_index, round_values.path_index);
            ctx.assign(sibling, round_values.sibling);
            ctx.assign(hash, round_values.hash);
        })
    });

    let merkle_last_step = ctx.step_type_def("merkle last step", |ctx| {
        ctx.setup(move |ctx| {
            ctx.transition(eq(path_index * (-path_index + 1), 0));
            ctx.constr(eq(hash, root));
        });

        ctx.wg(move |ctx, round_values: RoundValues<F>| {
            ctx.assign(leaf, round_values.leaf);
            ctx.assign(root, round_values.root);
            ctx.assign(path_index, round_values.path_index);
            ctx.assign(sibling, round_values.sibling);
            ctx.assign(hash, round_values.hash);
        })
    });
    ctx.pragma_first_step(&merkle_first_step);
    ctx.pragma_last_step(&merkle_last_step);
    ctx.pragma_num_steps(n_levels);

    ctx.trace(move |ctx, values| {
        let _hash = |a: F, b: F| (a * F::from(931)) + (b * F::from(2358));
        let mux_hash = |a, b, s: F| s * _hash(a, b) + (F::ONE - s) * _hash(b, a);
        let mut hash = values.leaf;
        ctx.add(
            &merkle_first_step,
            RoundValues {
                leaf: values.leaf,
                root: values.root,
                path_index: values.path_indices[0],
                sibling: values.siblings[0],
                hash,
            },
        );

        for i in 1..(n_levels - 1) {
            println!("path index length: {:?} {:?}", i, values.path_indices.len(),);
            hash = mux_hash(hash, values.siblings[i], values.path_indices[i]);
            ctx.add(
                &merkle_step,
                RoundValues {
                    leaf: values.leaf,
                    root: values.root,
                    path_index: values.path_indices[i],
                    sibling: values.path_indices[i],
                    hash,
                },
            );
        }

        hash = mux_hash(
            hash,
            values.siblings[n_levels - 1],
            values.path_indices[n_levels - 1],
        );
        ctx.add(
            &merkle_last_step,
            RoundValues {
                leaf: values.leaf,
                root: values.root,
                path_index: values.path_indices[n_levels - 1],
                sibling: values.path_indices[n_levels - 1],
                hash,
            },
        );
    })
}

fn merkle_super_circuit<F: PrimeField + Eq + Hash>(n_levels: usize) -> SuperCircuit<F, Inputs<F>> {
    super_circuit::<F, Inputs<F>, _>("merkle", |ctx| {
        let config = config(SingleRowCellManager {}, SimpleStepSelectorBuilder {});
        let (merkle, _) = ctx.sub_circuit(config, merkle_circuit, n_levels);

        ctx.mapping(move |ctx, values| {
            ctx.map(&merkle, values);
        })
    })
}

pub fn main() {
    let n_levels: usize = 11;
    let values = Inputs {
        leaf: Fr::ONE,
        root: Fr::ONE,
        path_indices: vec![Fr::ONE; n_levels],
        siblings: vec![Fr::ONE; n_levels],
    };

    let super_circuit = merkle_super_circuit::<Fr>(n_levels);
    let compiled = chiquitoSuperCircuit2Halo2(&super_circuit);
    let circuit =
        ChiquitoHalo2SuperCircuit::new(compiled, super_circuit.get_mapping().generate(values));

    let prover = MockProver::<Fr>::run(13, &circuit, Vec::new()).unwrap();
    let result = prover.verify_par();

    println!("res --- {:?}", result);
}
