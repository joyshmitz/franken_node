use tokio::runtime::{Builder as TokioBuilder};
fn main() {
    let _ = TokioBuilder::new_current_thread();
}
