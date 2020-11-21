//modules
mod d_ratchet;
mod traceback;
mod timing;
use crate::timing::*;


fn main() {
    println!("Testing on a short message (10 bytes)");
    println!();
    time_traceback(10, 1000);
    time_no_trace(10, 1000);

    /*println!();
    println!("Testing on a medium-short message (32 bytes)");
    println!();
    time_traceback(32, 1000);
    time_no_trace(32, 1000);

    println!();
    println!("Testing on a medium message (140 bytes)");
    println!();
    time_traceback(140, 1000);
    time_no_trace(140, 1000);

    println!();
    println!("Testing on a long message (300 bytes)");
    println!();
    time_traceback(300, 1000);
    time_no_trace(300, 1000);

    println!();
    println!("Testing on a very long message (500 bytes)");
    println!();
    time_traceback(500, 1000);
    time_no_trace(500, 1000);*/
}
