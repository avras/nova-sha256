# Nova-based SHA256
 
[Nova](https://github.com/microsoft/Nova) is a recursive SNARK that is suitable for computations with repeated structure, i.e. computations of the form $z_{i+1} = F(z_i)$. At each step, the function $F$ is allowed to have private inputs.

The SHA256 hash of a long input is computed by repeatedly applying the SHA256 compression function. At each step, the compression function consumes the previous 32-byte digest and a 64-byte block of the padded input. In the first step, a fixed initial value ($IV$) is used as the digest.

To use Nova to prove that the output of a message has a particular hash value, we can set $z_0 = IV$ and $F$ = SHA256 compression function. At each step, we provide the 64-byte message block as a private input.

## Running the example
Run the following commands.
```
cargo build --release
cargo run -r --example sha256 6
```
In the above case, The input message to SHA256 will be $2^6$ zero bytes. The output will look like the following.
```
Nova-based SHA256 compression function iterations
=========================================================
Producing public parameters...
PublicParams::setup, took 3.607127198s 
Number of constraints per step (primary circuit): 37034
Number of constraints per step (secondary circuit): 10347
Number of variables per step (primary circuit): 37000
Number of variables per step (secondary circuit): 10329
Generating a RecursiveSNARK...
RecursiveSNARK::prove_step 0: true, took 1.047µs 
RecursiveSNARK::prove_step 1: true, took 81.249423ms 
Total time taken by RecursiveSNARK::prove_steps: 81.283345ms
Verifying a RecursiveSNARK...
RecursiveSNARK::verify: true, took 71.64086ms
Generating a CompressedSNARK using Spartan with IPA-PC...
CompressedSNARK::prove: true, took 3.971226131s
Total proving time is 4.54092927s
CompressedSNARK::len 9938 bytes
Verifying a CompressedSNARK...
CompressedSNARK::verify: true, took 141.363763ms
=========================================================
Public parameters generation time: 3.607127198s 
Total proving time (excl pp generation): 4.54092927s
Total verification time: 141.363763ms
=========================================================
Expected value of final hash = "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
Actual value of final hash   = "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
```

To change the input length to 64 KB ($2^{16}$ bytes), run the following command. The input is again all zero bytes.
```
cargo run -r --example sha256 16
```

## Generating the benchmarks
Run the following commands (shell script tested only on Ubuntu).
```bash
cargo build --release --examples
./genlog_all.sh
```
The `logs` directory will have two files per input length `N`, for `N` in the set {64, 128, ..., 65536}.

- `output_N.txt` has the program output.
- `time_output_N.txt` has the output of the `time` command. This is used to measure peak memory usage.

To generate the logs for a particular length, you can run the `genlog.sh` script. For example, the following command will generate logs for input length 1024 bytes.
```
./genlog.sh 10
```
## Existing benchmarks
The existing files in the `logs` directory were generated on a Dell Inspiron laptop with a [11th Gen Intel i5-11320H CPU](https://ark.intel.com/content/www/us/en/ark/products/217183/intel-core-i511320h-processor-8m-cache-up-to-4-50-ghz-with-ipu.html) and 16 GB of RAM. The CPU has 4 cores with 2 threads per core.
- For all lengths
  - The peak memory usage was about 260 MB.
  - Verification time was less than 150 milliseconds.
  - Proof size was about 10,000 bytes.
  - Public parameter generation time was about 4 seconds
- The proving time for 64KB input was around 2 minutes. Proving times for other lengths are shown below.

### Proving times
```bash
$ grep "Total proving time is" $(ls logs/output_* -rt)
logs/output_65536.txt:Total proving time is 128.361272568s
logs/output_32768.txt:Total proving time is 67.385187591s
logs/output_16384.txt:Total proving time is 35.242403037s
logs/output_8192.txt:Total proving time is 19.427134991s
logs/output_4096.txt:Total proving time is 11.853209643s
logs/output_2048.txt:Total proving time is 8.10600355s
logs/output_1024.txt:Total proving time is 6.274435826s
logs/output_512.txt:Total proving time is 5.395036577s
logs/output_256.txt:Total proving time is 4.970008973s
logs/output_128.txt:Total proving time is 4.551801823s
logs/output_64.txt:Total proving time is 4.475632468s
```

### Verification times
```bash
$ grep "CompressedSNARK::verify" $(ls logs/output_* -rt)
logs/output_65536.txt:CompressedSNARK::verify: true, took 161.669379ms
logs/output_32768.txt:CompressedSNARK::verify: true, took 154.329705ms
logs/output_16384.txt:CompressedSNARK::verify: true, took 154.323314ms
logs/output_8192.txt:CompressedSNARK::verify: true, took 150.839038ms
logs/output_4096.txt:CompressedSNARK::verify: true, took 140.438199ms
logs/output_2048.txt:CompressedSNARK::verify: true, took 135.292959ms
logs/output_1024.txt:CompressedSNARK::verify: true, took 132.714996ms
logs/output_512.txt:CompressedSNARK::verify: true, took 139.134246ms
logs/output_256.txt:CompressedSNARK::verify: true, took 135.419974ms
logs/output_128.txt:CompressedSNARK::verify: true, took 133.126469ms
logs/output_64.txt:CompressedSNARK::verify: true, took 123.653851ms
```

### Proof sizes
```bash
$ grep "len" $(ls logs/output_* -rt)
logs/output_65536.txt:CompressedSNARK::len 9976 bytes
logs/output_32768.txt:CompressedSNARK::len 9975 bytes
logs/output_16384.txt:CompressedSNARK::len 9977 bytes
logs/output_8192.txt:CompressedSNARK::len 9971 bytes
logs/output_4096.txt:CompressedSNARK::len 9974 bytes
logs/output_2048.txt:CompressedSNARK::len 9972 bytes
logs/output_1024.txt:CompressedSNARK::len 9971 bytes
logs/output_512.txt:CompressedSNARK::len 9975 bytes
logs/output_256.txt:CompressedSNARK::len 9973 bytes
logs/output_128.txt:CompressedSNARK::len 9974 bytes
logs/output_64.txt:CompressedSNARK::len 9938 bytes
```

### Peak memory usage
```bash
$ grep "Maximum resident set size" $(ls logs/time_output_* -rt)
logs/time_output_65536.txt:     Maximum resident set size (kbytes): 261356
logs/time_output_32768.txt:     Maximum resident set size (kbytes): 265844
logs/time_output_16384.txt:     Maximum resident set size (kbytes): 260856
logs/time_output_8192.txt:      Maximum resident set size (kbytes): 266920
logs/time_output_4096.txt:      Maximum resident set size (kbytes): 262376
logs/time_output_2048.txt:      Maximum resident set size (kbytes): 264108
logs/time_output_1024.txt:      Maximum resident set size (kbytes): 261804
logs/time_output_512.txt:       Maximum resident set size (kbytes): 263784
logs/time_output_256.txt:       Maximum resident set size (kbytes): 262496
logs/time_output_128.txt:       Maximum resident set size (kbytes): 263340
logs/time_output_64.txt:        Maximum resident set size (kbytes): 262608
```
### Public parameter generation time
```bash
$ grep "Public parameters" $(ls logs/output_* -rt)
logs/output_65536.txt:Public parameters generation time: 3.612032586s 
logs/output_32768.txt:Public parameters generation time: 3.87279403s 
logs/output_16384.txt:Public parameters generation time: 3.920718336s 
logs/output_8192.txt:Public parameters generation time: 3.846917525s 
logs/output_4096.txt:Public parameters generation time: 3.795370968s 
logs/output_2048.txt:Public parameters generation time: 3.72987859s 
logs/output_1024.txt:Public parameters generation time: 3.679694828s 
logs/output_512.txt:Public parameters generation time: 3.720623095s 
logs/output_256.txt:Public parameters generation time: 3.717689922s 
logs/output_128.txt:Public parameters generation time: 3.662263553s 
logs/output_64.txt:Public parameters generation time: 3.597867008s
```


## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.