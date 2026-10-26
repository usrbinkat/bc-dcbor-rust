use hashbrown::HashTable;

#[derive(dcbor::CBORBoundedEncodable)]
struct Record<T> {
    #[cbor(n = 0)]
    value: T,
    #[cbor(n = 1)]
    optional: Option<u64>,
}

pub(super) fn exercise(data: &[u8]) {
    let seed = data.first().copied().unwrap_or(0) as usize;
    let data = &data[..data.len().min(128)];
    let mut source = HashTable::with_capacity((seed % 8) * 16);
    let mut expected = dcbor::Map::new();
    for (index, chunk) in data.chunks(8).enumerate().rev() {
        let mut key = HashTable::new();
        key.insert_unique(0, (0u64, index as u64), |_| 0);
        let mut key_map = dcbor::Map::new();
        key_map.insert(0u64, index as u64);
        let mut value = HashTable::with_capacity(chunk.len() * 8);
        let mut value_map = dcbor::Map::new();
        for (field, byte) in chunk.iter().enumerate().rev() {
            let text = if byte & 1 == 0 { "e\u{301}" } else { "a" }.repeat((byte % 4) as usize);
            value.insert_unique(field as u64, (field as u64, text.clone()), |(k, _)| *k);
            value_map.insert(field as u64, text);
        }
        let optional = (seed & 1 == 0).then_some(index as u64);
        source.insert_unique(index as u64, (key, Record { value, optional }), |_| 0);
        let mut record = dcbor::Map::new();
        record.insert(0u64, value_map);
        if let Some(value) = optional {
            record.insert(1u64, value);
        }
        expected.insert(key_map, record);
    }
    let bytes = dcbor::CBOR::from(expected).to_cbor_data();
    let bound = dcbor_test_support::prepare_turns(dcbor_test_support::shape(&source));
    super::schema::scheduled(&source, &bytes, seed * 257 + data.len(), bound);
}
