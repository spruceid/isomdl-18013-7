use rand::{distributions::Alphanumeric, Rng};

pub fn gen_nonce() -> String {
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    nonce
}
