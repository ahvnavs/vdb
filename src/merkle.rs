use crate::{
    error::{Result, StoreError, corruption},
    model::{DocumentMetadata, InclusionProof},
};

pub(crate) fn state_leaf(metadata: &DocumentMetadata) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vdb.state.leaf.v1\0");
    update_string(&mut hasher, &metadata.collection);
    update_string(&mut hasher, &metadata.id);
    hasher.update(&metadata.version.to_be_bytes());
    hasher.update(&metadata.created_sequence.to_be_bytes());
    hasher.update(&metadata.modified_sequence.to_be_bytes());
    hasher.update(&[u8::from(metadata.deleted)]);
    match &metadata.payload_hash {
        Some(hash) => {
            hasher.update(&[1]);
            update_string(&mut hasher, hash);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn build_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() {
        return *blake3::hash(b"vdb.state.empty.v1\0").as_bytes();
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| node(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
    }
    level[0]
}

pub(crate) fn build_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut level = leaves.to_vec();
    let mut position = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sibling = if position.is_multiple_of(2) {
            *level.get(position + 1).unwrap_or(&level[position])
        } else {
            level[position - 1]
        };
        siblings.push(sibling);
        level = level
            .chunks(2)
            .map(|pair| node(pair[0], *pair.get(1).unwrap_or(&pair[0])))
            .collect();
        position /= 2;
    }
    siblings
}

pub fn verify_inclusion_proof(proof: &InclusionProof) -> Result<()> {
    if proof.checkpoint.leaf_count == 0 || proof.leaf_index >= proof.checkpoint.leaf_count {
        return Err(StoreError::InvalidInput(
            "invalid Merkle proof position".into(),
        ));
    }
    let leaf = state_leaf(&proof.metadata);
    if hex::encode(leaf) != proof.leaf_hash {
        return Err(corruption("Merkle proof leaf mismatch"));
    }
    let mut current = leaf;
    let mut index = proof.leaf_index;
    let mut width = proof.checkpoint.leaf_count;
    for sibling in &proof.siblings {
        if width <= 1 {
            return Err(corruption("Merkle proof has excess siblings"));
        }
        let sibling: [u8; 32] = hex::decode(sibling)
            .map_err(corruption)?
            .try_into()
            .map_err(|_| corruption("invalid Merkle sibling length"))?;
        current = if index.is_multiple_of(2) {
            node(current, sibling)
        } else {
            node(sibling, current)
        };
        index /= 2;
        width = width.div_ceil(2);
    }
    if width != 1 || hex::encode(current) != proof.checkpoint.state_root {
        return Err(corruption("invalid Merkle inclusion proof"));
    }
    Ok(())
}

fn node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vdb.state.node.v1\0");
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

fn update_string(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}
