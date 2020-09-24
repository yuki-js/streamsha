use core::ops::*;

/// Performs circular right shift
pub fn rotr<T: Shl<usize, Output = T> + Shr<usize, Output = T> + BitOr<Output = T> + Copy>(
    x: T,
    n: usize,
) -> T {
    (x >> n) | (x << (core::mem::size_of::<T>() * 8 - n))
}
/// Performs circular left shift
#[allow(dead_code)]
pub fn rotl<T: Shl<usize, Output = T> + Shr<usize, Output = T> + BitOr<Output = T> + Copy>(
    x: T,
    n: usize,
) -> T {
    (x << n) | (x >> (core::mem::size_of::<T>() * 8 - n))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_equivalence() {
        assert_eq!(rotr(32u32, 2), rotl(32u32, 30));
        assert_eq!(rotr(32u64, 2), rotl(32u64, 62));
        assert_eq!(rotr((32u64), 2), rotl((32u64), 62));
    }
}
