# DOPoSt

# Requirements

* CryptoPP
* ABY

# Repository Structure
This repository consists of two folders:
* DPoSt: this folder is the evaluation code for the DOPoSt in the local process setting.
* DPoSt_2: this folder is the evaluation code for the DOPoSt in the outsourced process setting.

# Build Project
```
mkdir build 
cd build
cmake ..
make
```

# Run Project
For local setting
```
./post
./dpost
```
For outsourced setting
```
./dpost -r 0
./dpost -r 1
```
the evalutation result is print to the console.

# Disclaimer
This implementation is a research prototype and should not be used in production.
