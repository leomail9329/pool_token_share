use crate::viewing_key::VIEWING_KEY_SIZE;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use subtle::ConstantTimeEq;

        .as_slice()
        .try_into()
        .expect("Wrong password length")
}
