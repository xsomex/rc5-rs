#![feature(wrapping_int_impl)]

use std::{cmp::max, num::Wrapping, usize};

pub struct RC5<W> {
    expanded_key: Vec<Wrapping<W>>,
    nb_of_rounds: usize,
}

macro_rules! impl_rc5 {
    ($num_type: ty, $word_size: expr, $p: expr, $q: expr) => {
        impl RC5<$num_type> {
            pub fn encrypt(&self, a: $num_type, b: $num_type) -> ($num_type, $num_type) {
                let mut a = Wrapping(a);
                let mut b = Wrapping(b);

                a += self.expanded_key[0];
                b += self.expanded_key[1];

                for round in 1..(self.nb_of_rounds + 1) {
                    a = (a ^ b).rotate_left((b.0 % $word_size) as u32) + self.expanded_key[2 * round];
                    b = (b ^ a).rotate_left((a.0 % $word_size) as u32) + self.expanded_key[2 * round + 1];
                }

                (a.0, b.0)
            }

            pub fn decrypt(&self, a: $num_type, b: $num_type) -> ($num_type, $num_type) {
                let mut a = Wrapping(a);
                let mut b = Wrapping(b);

                for round in (1..(self.nb_of_rounds + 1)).rev() {
                    b = (b - self.expanded_key[2 * round + 1]).rotate_right((a.0 % $word_size) as u32) ^ a;
                    a = (a - self.expanded_key[2 * round]).rotate_right((b.0 % $word_size) as u32) ^ b;
                }

                b -= self.expanded_key[1];
                a -= self.expanded_key[0];

                (a.0, b.0)
            }

            pub fn new(key: Vec<u8>, nb_of_rounds: usize) -> RC5<$num_type> {
                let key_words_len =
                    key.len() / ($word_size / 8) + ((key.len() % ($word_size / 8) > 0) as usize);
                let mut key_words =
                    vec![Wrapping(<$num_type as From<$num_type>>::from(0)); key_words_len];

                for i in (0..key.len()).rev() {
                    key_words[i / ($word_size / 8)] = key_words[i / ($word_size / 8)]
                        .rotate_left(8)
                        + Wrapping(key[i] as $num_type);
                }

                let mut expanded_key =
                    vec![Wrapping(<$num_type as From<$num_type>>::from(0)); 2 * (nb_of_rounds + 1)];

                expanded_key[0] = Wrapping($p);

                for i in 1..(2 * (nb_of_rounds + 1)) {
                    expanded_key[i] = expanded_key[i - 1] + Wrapping($q);
                }

                let (mut i, mut j, mut a, mut b) = (
                    Wrapping(0usize),
                    Wrapping(0usize),
                    Wrapping(<$num_type as From<$num_type>>::from(0)),
                    Wrapping(<$num_type as From<$num_type>>::from(0)),
                );
                for _ in 0..3 * max(expanded_key.len(), key_words.len()) {
                    a = (expanded_key[i.0] + a + b).rotate_left(3);
                    expanded_key[i.0] = a;
                    b = (key_words[j.0] + a + b).rotate_left(((a + b).0 % $word_size) as u32);
                    key_words[j.0] = b;

                    i = Wrapping((i.0 + 1) % expanded_key.len());
                    j = Wrapping((j.0 + 1) % key_words.len());
                }

                RC5 {
                    expanded_key,
                    nb_of_rounds,
                }
            }
        }
    };
}

impl_rc5!(u16, 16, 0, 0);
impl_rc5!(u32, 32, 0xB7E1_5163, 0x9E37_79B9);
impl_rc5!(u64, 64, 0, 0);
