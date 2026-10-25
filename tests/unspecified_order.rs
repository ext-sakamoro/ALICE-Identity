//! ALICE-Law G13 (no unspecified order): the outputs that walk a collection come out in the order of the keys, not
//! in an order the standard library happens to produce. Each case is built so that an unordered collection could
//! answer either way: two equally short trust paths, trustees inserted out of order, and two mistyped claims.

use alice_identity::claim_schema::ClaimSchema;
use alice_identity::did::Did;
use alice_identity::errors::IdentityError;
use alice_identity::trust_graph::TrustGraph;
use std::collections::BTreeMap;

fn did(id: &str) -> Did {
    Did::new("example", id)
}

#[test]
fn of_two_equally_short_trust_paths_the_one_through_the_smaller_did_is_returned() {
    // a -> b -> d and a -> c -> d: both two hops; b sorts before c
    for order in [["c", "b"], ["b", "c"]] {
        let mut g = TrustGraph::new();
        for mid in order {
            g.add_trust(&did("a"), &did(mid));
            g.add_trust(&did(mid), &did("d"));
        }
        assert_eq!(
            g.trust_path(&did("a"), &did("d")),
            Some(vec![did("a"), did("b"), did("d")]),
            "insertion order {order:?}"
        );
    }
}

#[test]
fn trustees_come_back_in_did_order_whatever_the_insertion_order() {
    let mut g = TrustGraph::new();
    for id in ["m", "z", "a", "q"] {
        g.add_trust(&did("root"), &did(id));
    }
    assert_eq!(
        g.trustees_of(&did("root")),
        vec![did("a"), did("m"), did("q"), did("z")]
    );
}

#[test]
fn with_two_mistyped_claims_the_error_names_the_smaller_key() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("age", "integer");
    schema.add_required_field("born", "date");
    let mut claims = BTreeMap::new();
    claims.insert("born".to_string(), "yesterday".to_string());
    claims.insert("age".to_string(), "old".to_string());
    match schema.validate(&claims) {
        Err(IdentityError::InvalidClaimType { field, .. }) => assert_eq!(field, "age"),
        other => panic!("expected InvalidClaimType for age, got {other:?}"),
    }
}
