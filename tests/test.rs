use rc5::RC5;

#[test]
fn test() {
    let rc5 = RC5::<u64>::new(vec![2, 5, 4, 42, 87, 245], 32);
    let enc = rc5.encrypt(45, 54);
    assert_eq!((45, 54), rc5.decrypt(enc.0, enc.1));
}
