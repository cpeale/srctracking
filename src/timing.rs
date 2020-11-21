use rand_core::RngCore;
use rand_os::OsRng;
use std::time::Instant;

use crate::d_ratchet::*;
use crate::traceback::*;

pub fn time_traceback(length: usize, iters: u64) {
    //let plaintext = b"Hellooooo";
    let mut rng = OsRng::new().unwrap();
    let plat = Platform::new();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext = vec![0; length];
    rng.fill_bytes(&mut plaintext);

    let mut auth_sum = 0;
    let mut proc_sum = 0;
    let mut rec_sum = 0;
    let mut fwd_sum = 0;
    let mut rec_fwd_sum = 0;
    let mut rep_sum = 0;
    let mut total_auth_sum = 0;
    let mut total_fwd_sum = 0;

    for _ in 1..iters {
        //author
        let mut start = Instant::now();
        let (comm, e) = alice.author(&plaintext, &mut rng);
        let duration_send = start.elapsed();
        //process
        start = Instant::now();
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let duration_proc = start.elapsed();

        //receive author
        start = Instant::now();
        let (msg, fd) = bob.receive((sig, src, e), &plat);
        let duration_rec = start.elapsed();

        //report
        start = Instant::now();
        plat.process_report(msg.to_vec(), fd.to_vec());
        let duration_rep = start.elapsed();

        //fwd
        start = Instant::now();
        let (comm, e) = bob.fwd(&plaintext, fd, &mut rng);
        let duration_fwd = start.elapsed();

        let (sig, src) = plat.process_send(&bob.userid, &comm);

        //receive forward
        start = Instant::now();
        alice.receive((sig, src, e), &plat);
        let duration_rec_fwd = start.elapsed();

        //total time for author
        start = Instant::now();
        let (comm, e) = alice.author(&plaintext, &mut rng);
        let (sig, src) = plat.process_send(&alice.userid, &comm);
        let (_, fd) = bob.receive((sig, src, e), &plat);
        let duration_total_auth = start.elapsed();

        //total time for forward
        start = Instant::now();
        let (comm, e) = bob.fwd(&plaintext, fd, &mut rng);
        let (sig, src) = plat.process_send(&bob.userid, &comm);
        alice.receive((sig, src, e), &plat);
        let duration_total_fwd = start.elapsed();

        auth_sum = auth_sum + duration_send.as_nanos();
        proc_sum = proc_sum + duration_proc.as_nanos();
        rec_sum = rec_sum + duration_rec.as_nanos();
        fwd_sum = fwd_sum + duration_fwd.as_nanos();
        rec_fwd_sum = fwd_sum + duration_rec_fwd.as_nanos();
        rep_sum = rep_sum + duration_rep.as_nanos();
        total_auth_sum = total_auth_sum + duration_total_auth.as_nanos();
        total_fwd_sum = total_fwd_sum + duration_total_fwd.as_nanos();
    }

    let denom = iters as f64 * 1000000.0;
    let auth_avg = auth_sum as f64 / denom;
    let proc_avg = proc_sum as f64 / denom;
    let rec_avg = rec_sum as f64 / denom;
    let fwd_avg = fwd_sum as f64 / denom;
    let rec_fwd_avg = rec_fwd_sum as f64 / denom;
    let rep_avg = rep_sum as f64 / denom;
    let total_auth_avg = total_auth_sum as f64 / denom;
    let total_fwd_avg = total_fwd_sum as f64 / denom;
    println!("------------------- TRACEBACK STATS -----------------------");
    println!("Authoring a message: {:}ms", auth_avg);
    println!("Forwarding a message: {:}ms", fwd_avg);
    println!();
    println!("Processing a message: {:}ms", proc_avg);
    println!();
    println!("Receiving an authored message: {:}ms", rec_avg);
    println!("Receiving a forwarded message: {:}ms", rec_fwd_avg);
    println!();
    println!("Reporting a message: {:}ms", rep_avg);
    println!();
    println!("Total time for an authored message: {:}ms", total_auth_avg);
    println!("Total time for a forwarded message: {:}ms", total_fwd_avg);
    println!();
}

pub fn time_no_trace(length: usize, iters: u64) {
    let mut rng = OsRng::new().unwrap();
    let (mut alice, mut bob) = User::new(&mut rng);
    let mut plaintext = vec![0; length];
    rng.fill_bytes(&mut plaintext);

    let mut send_sum_wo_trace = 0;
    let mut rec_sum_wo_trace = 0;
    let mut total_sum_wo_trace = 0;

    for _ in 1..iters {
        let mut start = Instant::now();
        let (h, ct) = alice.msg_scheme.ratchet_encrypt(&plaintext, AD, &mut rng);
        let duration_send = start.elapsed();
        start = Instant::now();
        bob.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let duration_rec = start.elapsed();

        start = Instant::now();
        let (h, ct) = bob.msg_scheme.ratchet_encrypt(&plaintext, AD, &mut rng);
        alice.msg_scheme.ratchet_decrypt(&h, &ct, AD).unwrap();
        let duration_total = start.elapsed();

        send_sum_wo_trace = send_sum_wo_trace + duration_send.as_nanos();
        rec_sum_wo_trace = rec_sum_wo_trace + duration_rec.as_nanos();
        total_sum_wo_trace = total_sum_wo_trace + duration_total.as_nanos();
    }

    let avg_send = send_sum_wo_trace as f64 / (iters as f64 * 1000000.0);
    let avg_rec = rec_sum_wo_trace as f64 / (iters as f64 * 1000000.0);
    let avg_total = total_sum_wo_trace as f64 / (iters as f64 * 1000000.0);

    println!("------------------- STATS WITHOUT TRACEBACK -----------------------");
    println!("Sending a message: {:}ms", avg_send);
    println!("Receiving a message: {:}ms", avg_rec);
    println!();
    println!("Total time: {:}ms", avg_total);
}