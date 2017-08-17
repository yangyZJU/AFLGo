# AFLGo: Directed Greybox Fuzzing
<a href="https://comp.nus.edu.sg/~mboehme/paper/CCS17.pdf" target="_blank"><img src="https://comp.nus.edu.sg/~mboehme/paper/CCS17.png" align="right" width="250"></a>
AFLGo is an extension of <a href="https://lcamtuf.coredump.cx/afl/" target="_blank">American Fuzzy Lop (AFL)</a>.
Given a set of target locations (e.g., `folder/file.c:582`), AFLGo generates inputs specifically with the objective to exercise these target locations.

Unlike AFL, AFLGo spends most of its time budget on reaching specific target locations without wasting resources stressing unrelated program components. This is particularly interesting in the context of
* **patch testing** by setting changed statements as targets. When a critical component is changed, we would like to check whether this introduced any vulnerabilities. AFLGo, a fuzzer that can focus on those changes, has a higher chance of exposing the regression.
* **static analysis report verification** by setting statements as targets that a static analysis reports as potentially dangerous or vulnerability-inducing. When assessing the security of a program, static analysis tools might identify dangerous locations, such as critical system calls. AFLGo can generate inputs that actually show that this is indeed no false positive.
* **information flow detection** by setting sensitive sources and sinks as targets. To expose data leakage vulnerabilities, a security researcher would like to generate executions that exercise sensitive sources containing private information and sensitive sinks where data becomes visible to the outside world. A directed fuzzer can be used to generate such executions efficiently.
* **crash reproduction**  by setting method calls in the stack-trace as targets. When in-field crashes are reported, only the stack-trace and some environmental parameters are sent to the in-house development team. To preserve the user's privacy, the specific crashing input is often not available. AFLGo could help the in-house team to swiftly reproduce these crashes.

# Integration into OSS-Fuzz
The easiest way to use AFLGo is as patch testing tool in OSS-Fuzz. Here is our integration:
* https://github.com/aflgo/oss-fuzz

# How to instrument a Binary with AFLGo
1) Install <a href="https://llvm.org/docs/CMake.html" target="_blank">LLVM</a> with <a href="http://llvm.org/docs/GoldPlugin.html" target="_blank">Gold</a>-plugin. You can also follow <a href="https://github.com/aflgo/oss-fuzz/blob/master/infra/base-images/base-clang/checkout_build_install_llvm.sh" target="_blank">these</a> instructions.
2) Install other prerequisite
```bash
sudo apt-get install python3
sudo apt-get install python3-pip
sudo pip3 install --upgrade pip
sudo pip3 install networkx
sudo pip3 install pydotplus
```
3) Compile AFLGo fuzzer and LLVM-instrumentation pass
```bash
# Checkout source code
git clone https://github.com/aflgo/aflgo.git
export AFLGO=$PWD/aflgo

# Compile source code
pushd $AFLGO
make clean all 
cd llvm_mode
make clean all
popd
```
4) Download subject (<a href="http://www.darwinsys.com/file/" target="_blank">file</a>-utility)
```bash
# Clone subject repository
git clone https://github.com/file/file.git
export SUBJECT=$PWD/file
```
5) Set targets (changed statements in commit <a href="https://github.com/file/file/commit/69928a2" target="_blank">69928a2</a>). Writes BBtargets.txt.
```bash
# Setup directory containing all temporary files
mkdir temp
export TMP_DIR=$PWD/temp

# Download commit-analysis tool
wget https://raw.githubusercontent.com/jay/showlinenum/develop/showlinenum.awk
chmod +x showlinenum.awk
mv showlinenum.awk $TMP_DIR

# Generate BBtargets from commit 69928a2
pushd $SUBJECT
  git checkout 69928a2
  git diff -U0 HEAD^ HEAD > $TMP_DIR/commit.diff
popd
cat $TMP_DIR/commit.diff |  $TMP_DIR/showlinenum.awk show_header=0 path=1 | grep -e "\.[ch]:[0-9]*:+" -e "\.cpp:[0-9]*:+" -e "\.cc:[0-9]*:+" | cut -d+ -f1 | rev | cut -c2- | rev > $TMP_DIR/BBtargets.txt

# Print extracted targets. 
echo "Targets:"
cat $TMP_DIR/BBtargets.txt
```
6) **Note**: If there are no targets, there is nothing to instrument!
7) Generate CG and intra-procedural CFGs from subject (file-utility).
```bash
# Set aflgo-instrumenter
export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++

# Set aflgo-instrumentation flags
export COPY_CFLAGS=$CFLAGS
export COPY_CXXFLAGS=$CXXFLAGS
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export CFLAGS="$CFLAGS $ADDITIONAL"
export CXXFLAGS="$CXXFLAGS $ADDITIONAL"

# Build file-utility (in order to generate CG and CFGs)
pushd $SUBJECT
  autoreconf -i
  ./configure --enable-static
  make V=1 all -j$(nproc)
popd

# Test whether build was successful 
$SUBJECT/src/file -m $SUBJECT/magic/magic.mgc $SUBJECT/src/file

# Test whether CG/CFG extraction was successful
ls $TMP_DIR/dot-files
echo "Function targets"
cat $TMP_DIR/Ftargets.txt

# Clean up
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

# Generate distance
$AFLGO/scripts/genDistance.sh $SUBJECT/src $TMP_DIR file

# Check distance file
tail $TMP_DIR/distance.cfg.txt
```
8) Note: If `distance.cfg.txt` is empty, there was some problem computing the CG-level and BB-level target distance. See `$TMP_DIR/step*`.
9) Instrument subject (file-utility)
```bash
export CFLAGS="$COPY_CFLAGS -distance=$TMP_DIR/distance.cfg.txt"
export CXXFLAGS="$COPY_CXXFLAGS -distance=$TMP_DIR/distance.cfg.txt"
pushd $SUBJECT
  make clean all -j$(nproc)
popd
```

# How to fuzz the instrumented binary
* We set the exponential annealing-based power schedule (-z exp).
* We set the time-to-exploitation to 45min (-c 45m), assuming the fuzzer is run for about an hour.
```bash
# Prepare seed corpus for file-utility
mkdir in
find $AFLGO/testcases/ -type f -exec cp {} in \;

# Start fuzzer
$AFLGO/afl-fuzz -d -i in -o out -m none -z exp -c 45m \
       $SUBJECT/src/file -m $SUBJECT/magic.mgc @@
```

