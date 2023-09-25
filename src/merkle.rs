use chiquito::ast::{query::Queriable, Expr};
use chiquito::frontend::dsl::CircuitContext;
use halo2curves::ff::PrimeField;
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

        for i in 0..n_levels {
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

pub fn main() {}
