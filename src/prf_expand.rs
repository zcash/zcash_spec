use core::marker::PhantomData;

use blake2b_simd::Params;

const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// The set of domains in which $PRF^\mathsf{expand}$ is defined.
///
/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/protocol.pdf#concreteprfs
pub struct PrfExpand<T> {
    domain_separator: u8,
    _input: PhantomData<T>,
}

impl<T> PrfExpand<T> {
    /// Defines a new $PRF^\mathsf{expand}$ domain.
    ///
    /// Private because we want to ensure that all domains are defined in the same place,
    /// to avoid bugs where a domain separator is accidentally reused.
    const fn new(domain_separator: u8) -> Self {
        Self {
            domain_separator,
            _input: PhantomData,
        }
    }

    /// Expands the given secret key in this domain, with additional data concatenated
    /// from the given slices.
    ///
    /// $PRF^\mathsf{expand}(sk, dst, a, b, ...) := BLAKE2b-512("Zcash_ExpandSeed", sk || dst || a || b || ...)$
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
    ///
    /// [concreteprfs]: https://zips.z.cash/protocol/protocol.pdf#concreteprfs
    fn apply(self, sk: &[u8], ts: &[&[u8]]) -> [u8; 64] {
        let mut h = Params::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(sk);
        h.update(&[self.domain_separator]);
        for t in ts {
            h.update(t);
        }
        *h.finalize().as_array()
    }
}

/// Marker type used for `PrfExpand` instantiations that permit a variable-length input.
pub struct VariableLengthSlice;

macro_rules! with_inputs {
    ($($arr:ident, $arrlen:ident),*) => {
        #[allow(unused_parens)]
        impl<$(const $arrlen: usize),*> PrfExpand<($([u8; $arrlen]),*)> {
            /// Expands the given secret key in this domain.
            pub fn with(self, sk: &[u8], $($arr: &[u8; $arrlen]),*) -> [u8; 64] {
                self.apply(sk, &[$($arr),*])
            }
        }
    };
}

impl PrfExpand<()> {
    pub const SAPLING_ASK: Self = Self::new(0x00);
    pub const SAPLING_NSK: Self = Self::new(0x01);
    pub const SAPLING_OVK: Self = Self::new(0x02);
    pub const SAPLING_RCM: Self = Self::new(0x04);
    pub const SAPLING_ESK: Self = Self::new(0x05);
    pub const ORCHARD_ASK: Self = Self::new(0x06);
    pub const ORCHARD_NK: Self = Self::new(0x07);
    pub const ORCHARD_RIVK: Self = Self::new(0x08);
    pub const SAPLING_ZIP32_MASTER_DK: Self = Self::new(0x10);
    pub const SAPLING_ZIP32_CHILD_I_ASK: Self = Self::new(0x13);
    pub const SAPLING_ZIP32_CHILD_I_NSK: Self = Self::new(0x14);
    pub const SAPLING_ZIP32_INTERNAL_NSK: Self = Self::new(0x17);
    pub const SAPLING_ZIP32_INTERNAL_DK_OVK: Self = Self::new(0x18);
}
with_inputs!();

impl PrfExpand<[u8; 1]> {
    pub const SAPLING_DEFAULT_DIVERSIFIER: Self = Self::new(0x03);
}
impl PrfExpand<[u8; 32]> {
    pub const ORCHARD_ESK: Self = Self::new(0x04);
    pub const ORCHARD_RCM: Self = Self::new(0x05);
    pub const PSI: Self = Self::new(0x09);
    pub const SAPLING_ZIP32_CHILD_OVK: Self = Self::new(0x15);
    pub const SAPLING_ZIP32_CHILD_DK: Self = Self::new(0x16);
}
impl PrfExpand<[u8; 33]> {
    pub const TRANSPARENT_ZIP316_OVK: Self = Self::new(0xD0);
}
with_inputs!(a, A);

impl PrfExpand<([u8; 32], [u8; 4])> {
    pub const SPROUT_ZIP32_CHILD: Self = Self::new(0x80);
}
impl PrfExpand<([u8; 32], [u8; 32])> {
    pub const ORCHARD_DK_OVK: Self = Self::new(0x82);
    pub const ORCHARD_RIVK_INTERNAL: Self = Self::new(0x83);
}
with_inputs!(a, A, b, B);

impl PrfExpand<([u8; 32], [u8; 32], [u8; 8], [u8; 32], [u8; 32])> {
    /// The ZIP 2005 domain for deriving Orchard note commitment randomness
    /// for quantum-recoverable notes.
    pub const ORCHARD_QR_RCM: Self = Self::new(0x0B);
}
with_inputs!(a, A, b, B, c, C, d, D, e, E);

impl PrfExpand<([u8; 96], [u8; 32], [u8; 4])> {
    pub const SAPLING_ZIP32_CHILD_HARDENED: Self = Self::new(0x11);
    pub const SAPLING_ZIP32_CHILD_NON_HARDENED: Self = Self::new(0x12);
}
with_inputs!(a, A, b, B, c, C);

impl PrfExpand<([u8; 32], [u8; 4], [u8; 1], VariableLengthSlice)> {
    pub const ORCHARD_ZIP32_CHILD: Self = Self::new(0x81);
    pub const ADHOC_ZIP32_CHILD: Self = Self::new(0xAB);
    pub const REGISTERED_ZIP32_CHILD: Self = Self::new(0xAC);

    /// Expands the given secret key in this domain.
    pub fn with(self, sk: &[u8], a: &[u8; 32], b: &[u8; 4], c: &[u8; 1], d: &[u8]) -> [u8; 64] {
        if c == &[0] && d.is_empty() {
            self.apply(sk, &[a, b])
        } else {
            self.apply(sk, &[a, b, c, d])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PrfExpand, PRF_EXPAND_PERSONALIZATION};
    use blake2b_simd::Params;

    #[test]
    fn orchard_qr_rcm_matches_zip_2005_preimage() {
        let rseed = [0x10; 32];
        let g_d = [0x20; 32];
        let pk_d = [0x30; 32];
        let value = 0x0102_0304_0506_0708u64.to_le_bytes();
        let rho = [0x40; 32];
        let psi = [0x50; 32];

        let actual = PrfExpand::ORCHARD_QR_RCM.with(&rseed, &g_d, &pk_d, &value, &rho, &psi);

        let mut h = Params::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state();
        h.update(&rseed);
        h.update(&[0x0B]);
        h.update(&g_d);
        h.update(&pk_d);
        h.update(&value);
        h.update(&rho);
        h.update(&psi);

        assert_eq!(actual, *h.finalize().as_array());
    }
}
