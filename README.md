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
PublicParams::setup, took 2.611468601s 
Number of constraints per step (primary circuit): 37034
Number of constraints per step (secondary circuit): 10347
Number of variables per step (primary circuit): 37000
Number of variables per step (secondary circuit): 10329
Generating a RecursiveSNARK...
RecursiveSNARK::prove_step 0: true, took 82.511139ms 
RecursiveSNARK::prove_step 1: true, took 130.959699ms 
Total time taken by RecursiveSNARK::prove_steps: 213.520633ms
Verifying a RecursiveSNARK...
RecursiveSNARK::verify: true, took 105.580201ms
Generating a CompressedSNARK using Spartan with IPA-PC...
CompressedSNARK::prove: true, took 5.661125515s
Total prover time is 8.051336343s
CompressedSNARK::len 10038 bytes
Verifying a CompressedSNARK...
CompressedSNARK::verify: true, took 185.780213ms
=========================================================
Public parameters generation time: 2.611468601s 
Total prover time (excl pp generation): 8.051336343s
Total verification time: 185.780213ms
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
  - The peak memory usage was about 190 MB.
  - Verification time was less than 200 milliseconds.
  - Proof size was about 10,000 bytes.
  - Public parameter generation time was about 2 seconds
- The proving time for 64KB input was less than 3 minutes. Proving times for other lengths are shown below.

### Proving times
```bash
$ grep "Total proving time is" $(ls logs/output_* -rt)
logs/output_65536.txt:Total proving time is 153.329723483s
logs/output_32768.txt:Total proving time is 83.317435157s
logs/output_16384.txt:Total proving time is 44.416323182s
logs/output_8192.txt:Total proving time is 25.07357382s
logs/output_4096.txt:Total proving time is 15.447993575s
logs/output_2048.txt:Total proving time is 10.738355661s
logs/output_1024.txt:Total proving time is 8.52078857s
logs/output_512.txt:Total proving time is 7.632562739s
logs/output_256.txt:Total proving time is 6.942968695s
logs/output_128.txt:Total proving time is 6.637955792s
logs/output_64.txt:Total proving time is 6.515439507s
```

### Verification times
```bash
$ grep "CompressedSNARK::verify" $(ls logs/output_* -rt)
logs/output_65536.txt:CompressedSNARK::verify: true, took 166.459033ms
logs/output_32768.txt:CompressedSNARK::verify: true, took 172.649659ms
logs/output_16384.txt:CompressedSNARK::verify: true, took 162.629372ms
logs/output_8192.txt:CompressedSNARK::verify: true, took 164.985758ms
logs/output_4096.txt:CompressedSNARK::verify: true, took 153.084282ms
logs/output_2048.txt:CompressedSNARK::verify: true, took 149.644821ms
logs/output_1024.txt:CompressedSNARK::verify: true, took 136.47942ms
logs/output_512.txt:CompressedSNARK::verify: true, took 147.028666ms
logs/output_256.txt:CompressedSNARK::verify: true, took 142.876465ms
logs/output_128.txt:CompressedSNARK::verify: true, took 144.707355ms
logs/output_64.txt:CompressedSNARK::verify: true, took 139.618166ms
```

### Proof sizes
```bash
$ grep "len" $(ls logs/output_* -rt)
logs/output_65536.txt:CompressedSNARK::len 10077 bytes
logs/output_32768.txt:CompressedSNARK::len 10075 bytes
logs/output_16384.txt:CompressedSNARK::len 10076 bytes
logs/output_8192.txt:CompressedSNARK::len 10074 bytes
logs/output_4096.txt:CompressedSNARK::len 10070 bytes
logs/output_2048.txt:CompressedSNARK::len 10075 bytes
logs/output_1024.txt:CompressedSNARK::len 10070 bytes
logs/output_512.txt:CompressedSNARK::len 10072 bytes
logs/output_256.txt:CompressedSNARK::len 10069 bytes
logs/output_128.txt:CompressedSNARK::len 10074 bytes
logs/output_64.txt:CompressedSNARK::len 10038 bytes
```

### Peak memory usage
```bash
$ grep "Maximum resident set size" $(ls logs/time_output_* -rt)
logs/time_output_65536.txt:     Maximum resident set size (kbytes): 189124
logs/time_output_32768.txt:     Maximum resident set size (kbytes): 185732
logs/time_output_16384.txt:     Maximum resident set size (kbytes): 188660
logs/time_output_8192.txt:      Maximum resident set size (kbytes): 189748
logs/time_output_4096.txt:      Maximum resident set size (kbytes): 185940
logs/time_output_2048.txt:      Maximum resident set size (kbytes): 189444
logs/time_output_1024.txt:      Maximum resident set size (kbytes): 191332
logs/time_output_512.txt:       Maximum resident set size (kbytes): 185540
logs/time_output_256.txt:       Maximum resident set size (kbytes): 189904
logs/time_output_128.txt:       Maximum resident set size (kbytes): 187456
logs/time_output_64.txt:        Maximum resident set size (kbytes): 186700
```
### Public parameter generation time
```bash
$ grep "Public parameters" $(ls logs/output_* -rt)
logs/output_65536.txt:Public parameters generation time: 2.108299971s 
logs/output_32768.txt:Public parameters generation time: 2.376485699s 
logs/output_16384.txt:Public parameters generation time: 2.328711461s 
logs/output_8192.txt:Public parameters generation time: 2.383944439s 
logs/output_4096.txt:Public parameters generation time: 2.272826069s 
logs/output_2048.txt:Public parameters generation time: 2.307919212s 
logs/output_1024.txt:Public parameters generation time: 2.235006997s 
logs/output_512.txt:Public parameters generation time: 2.276651869s 
logs/output_256.txt:Public parameters generation time: 2.224695874s 
logs/output_128.txt:Public parameters generation time: 2.231766552s 
logs/output_64.txt:Public parameters generation time: 2.22830318s 
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