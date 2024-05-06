

# Binary Plaintext Checking oracle based SCA Demo on ML-KEM
:warning: **This code is for demonstrative purposes!** :warning:

This code demonstrates Binary Plaintext Checking (PC) Oracle based Side-Channel Analysis on Module Lattice Key Encapsulation Mechanism (ML-KEM). ML-KEM is based on [Dilithium](https://pq-crystals.org/kyber/).

## Environment

### Local Environment
* Clone this repository
```commandline
git clone --recurse-submodules https://github.com/PRASANNA-RAVI/SCA_ML_KEM_Demo.git
```

* Compile the Code as follows:
```commandline
make run_kyber512
make run_kyber768
make run_kyber1024
```

* Run the Code as follows:
```commandline
./run_kyber512
./run_kyber768
./run_kyber1024
```

### Cloud Environment
1. Go to [C Online Compiler & Interpreter based on Replit](https://replit.com/languages/C)
2. Create an account on Replit
3. You can import code from [this github link](https://github.com/PRASANNA-RAVI/SCA_ML_KEM_Demo.git) or you can just import local files from machine.