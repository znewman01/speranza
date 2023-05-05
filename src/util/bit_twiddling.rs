pub(crate) use digest::generic_array::{ArrayLength, GenericArray};

pub fn mask<N: ArrayLength<u8>>(data: &GenericArray<u8, N>, bits: usize) -> GenericArray<u8, N> {
    let mut data = data.clone();
    if bits == data.len() * 8 {
        return data;
    }
    let byte_idx = bits / 8;
    let bit_idx = bits % 8;
    // keep `bit_idx` bits of the `byte_idx`th byte
    if bit_idx != 0 {
        data[byte_idx] &= (1u8 << (8 - bit_idx)).wrapping_neg();
    } else {
        data[byte_idx] = 0;
    }
    // zero out everything after
    for i in (byte_idx + 1)..data.len() {
        data[i] = 0;
    }
    data
}

pub fn get_bit_i(data: &[u8], bit: usize) -> bool {
    let byte: u8 = data[bit / 8];
    byte & (1u8 << (7 - bit % 8)) != 0
}

pub fn set_bit_i(data: &mut [u8], bit: usize, value: bool) {
    if value {
        data[bit / 8] |= 1u8 << (7 - bit % 8);
    } else {
        data[bit / 8] &= !(1u8 << (7 - bit % 8));
    }
}

pub fn flip_bit_i(data: &mut [u8], bit: usize) {
    let old_value = get_bit_i(data, bit);
    set_bit_i(data, bit, !old_value)
}

pub fn shared_prefix_length<N: ArrayLength<u8>>(
    data: GenericArray<u8, N>,
    other: GenericArray<u8, N>,
) -> usize {
    let total_bits = N::to_usize() * 8;
    for i in 0..total_bits {
        if get_bit_i(data.as_ref(), i) != get_bit_i(other.as_ref(), i) {
            return i;
        }
    }
    total_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::generic_array::arr;
    use digest::generic_array::typenum;
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::*;
    use proptest::sample::Index;

    fn data() -> impl Strategy<Value = Vec<u8>> {
        prop_vec(any::<u8>(), 1..10)
    }

    #[test]
    fn test_get_ith_bit() {
        let data = [0b01010101, 0b01010101];
        assert_eq!(get_bit_i(&data, 0), false);
        assert_eq!(get_bit_i(&data, 1), true);
        assert_eq!(get_bit_i(&data, 2), false);
        assert_eq!(get_bit_i(&data, 3), true);
        assert_eq!(get_bit_i(&data, 7), true);
        assert_eq!(get_bit_i(&data, 8), false);
        assert_eq!(get_bit_i(&data, 15), true);
    }

    proptest! {
        #[test]
        #[should_panic]
        fn test_get_ith_bit_bad_bit(data in data(), extra_idx: usize) {
            prop_assume!(extra_idx > 0);
            let bit = data.len() * 8 + extra_idx;
            get_bit_i(&data, bit);
        }
    }

    #[test]
    fn test_set_ith_bit() {
        let mut data = [0b01010101, 0b01010101];
        set_bit_i(&mut data, 0, false);
        assert_eq!(data, [0b01010101, 0b01010101]);
        set_bit_i(&mut data, 0, true);
        assert_eq!(data, [0b11010101, 0b01010101]);
        set_bit_i(&mut data, 1, false);
        assert_eq!(data, [0b10010101, 0b01010101]);
        set_bit_i(&mut data, 1, true);
        assert_eq!(data, [0b11010101, 0b01010101]);
        set_bit_i(&mut data, 7, false);
        assert_eq!(data, [0b11010100, 0b01010101]);
        set_bit_i(&mut data, 8, true);
        assert_eq!(data, [0b11010100, 0b11010101]);
    }

    #[test]
    fn test_flip_ith_bit() {
        let mut data = [0b01010101, 0b01010101];
        flip_bit_i(&mut data, 0);
        assert_eq!(data, [0b11010101, 0b01010101]);
        flip_bit_i(&mut data, 0);
        assert_eq!(data, [0b01010101, 0b01010101]);
        flip_bit_i(&mut data, 1);
        assert_eq!(data, [0b00010101, 0b01010101]);
        flip_bit_i(&mut data, 1);
        assert_eq!(data, [0b01010101, 0b01010101]);
        flip_bit_i(&mut data, 7);
        assert_eq!(data, [0b01010100, 0b01010101]);
        flip_bit_i(&mut data, 8);
        assert_eq!(data, [0b01010100, 0b11010101]);
    }

    proptest! {
        /// Tests that setting a bit to the same value twice resuls in the same outcome.
        #[test]
        fn test_set_ith_bit_idempotent(mut data in data(), index: Index, value: bool) {
            let bit = index.index(data.len() * 8);
            set_bit_i(&mut data, bit, value);
            let once = data.clone();
            set_bit_i(&mut data, bit, value);
            let twice = data;
            assert_eq!(once, twice);
        }

        /// Tests that getting bit `i` after setting it to `value` gives `value`.
        #[test]
        fn test_set_then_get_ith_bit(mut data in data(), index: Index, value: bool) {
            let bit = index.index(data.len() * 8);
            set_bit_i(&mut data, bit, value);
            assert_eq!(get_bit_i(&data, bit), value);
        }

        /// Tests that flipping the ith bit doesn't affect any bit *other* than i.
        #[test]
        fn test_set_ith_bit_others_unaffected(mut data in data(), index: Index, other_index: Index, value: bool) {
            let bit = index.index(data.len() * 8);
            let other_bit = other_index.index(data.len() * 8);
            prop_assume!(bit != other_bit);

            let old_value = get_bit_i(&data, bit);
            set_bit_i(&mut data, other_bit, value);
            assert_eq!(get_bit_i(&data, bit), old_value);
        }

        /// Tests that flip_ith_bit twice is the identity operation.
        #[test]
        fn test_flip_ith_bit_twice(mut data in data(), index: Index) {
            let old_data = data.clone();
            let bit = index.index(data.len() * 8);
            flip_bit_i(&mut data, bit);
            assert_ne!(old_data, data);
            flip_bit_i(&mut data, bit);
            assert_eq!(old_data, data);
        }

        #[test]
        fn test_flip_ith_bit_others_unaffected(mut data in data(), index: Index, other_index: Index) {
            let bit = index.index(data.len() * 8);
            let other_bit = other_index.index(data.len() * 8);
            prop_assume!(bit != other_bit);

            let old_value = get_bit_i(&data, bit);
            flip_bit_i(&mut data, other_bit);
            assert_eq!(get_bit_i(&data, bit), old_value);
        }

        #[test]
        #[should_panic]
        fn test_set_ith_bit_bad_bit(mut data in data(), extra_idx: usize, value: bool) {
            prop_assume!(extra_idx > 0);
            let bit = data.len() * 8 + extra_idx;
            set_bit_i(&mut data, bit, value);
        }
    }

    fn data_array() -> impl Strategy<Value = GenericArray<u8, typenum::U2>> {
        (any::<u8>(), any::<u8>()).prop_map(|(a, b)| arr![u8; a, b])
    }

    #[test]
    fn test_mask() {
        let data = arr![u8; 0b11111111, 0b11000011];
        assert_eq!(mask(&data, 0), arr![u8; 0b00000000, 0b00000000]);
        assert_eq!(mask(&data, 1), arr![u8; 0b10000000, 0b00000000]);
        assert_eq!(mask(&data, 2), arr![u8; 0b11000000, 0b00000000]);
        assert_eq!(mask(&data, 8), arr![u8; 0b11111111, 0b00000000]);
        assert_eq!(mask(&data, 9), arr![u8; 0b11111111, 0b10000000]);
        assert_eq!(mask(&data, 15), arr![u8; 0b11111111, 0b11000010]);
        assert_eq!(mask(&data, 16), arr![u8; 0b11111111, 0b11000011]);
    }

    proptest! {
        #[test]
        #[should_panic]
        fn test_mask_too_big(data in data_array(), extra_idx: usize) {
            prop_assume!(extra_idx > 0);
            mask(&data, data.len() *8 + extra_idx);
        }
    }

    #[test]
    fn test_shared_prefix_length() {
        let test_cases = vec![
            (arr![u8; 0b00000000], arr![u8; 0b10000000], 0),
            (arr![u8; 0b00000000], arr![u8; 0b01000000], 1),
            (arr![u8; 0b00000000], arr![u8; 0b00000001], 7),
            (arr![u8; 0b00000000], arr![u8; 0b00000000], 8),
        ];
        for (data, other, expected) in test_cases {
            assert_eq!(shared_prefix_length(data, other), expected);
        }

        let test_cases = vec![
            (
                arr![u8; 0b00000000, 0b00000000],
                arr![u8; 0b00000000, 0b10000000],
                8,
            ),
            (
                arr![u8; 0b00000000, 0b00000000],
                arr![u8; 0b00000000, 0b01000000],
                9,
            ),
            (
                arr![u8; 0b00000000, 0b00000000],
                arr![u8; 0b00000000, 0b00000001],
                15,
            ),
            (
                arr![u8; 0b00000000, 0b00000000],
                arr![u8; 0b00000000, 0b00000000],
                16,
            ),
        ];
        for (data, other, expected) in test_cases {
            assert_eq!(shared_prefix_length(data, other), expected);
        }
    }

    proptest! {
        /// Tests that the shared prefix length between `data` and `data` with bit `i` flipped is `i`.
        #[test]
        fn test_shared_prefix_length_is_flipped_bit(data in data_array(), index: Index) {
            let mut other = data.clone();
            let bit = index.index(data.len() * 8);
            flip_bit_i(other.as_mut(), bit);
            assert_eq!(shared_prefix_length(data, other), bit);
        }
    }
}
