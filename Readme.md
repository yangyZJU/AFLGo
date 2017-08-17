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

# How to use AFLGo
1) Install <a href="https://llvm.org/docs/CMake.html" target="_blank">LLVM</a> with <a href="http://llvm.org/docs/GoldPlugin.html" target="_blank">Gold</a>-plugin.
2) Compile AFLGo fuzzer and LLVM-instrumentation pass
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
3) Download subject (<a href="http://www.darwinsys.com/file/" target="_blank">file</a>-utility) and set targets (commit <a href="https://github.com/file/file/commit/69928a2" target="_blank">69928a2</a>)
```bash
# Clone subject repository
git clone https://github.com/file/file.git

# Checkout revision 69928a2
cd file && git checkout 69928a2 && cd ..
export SUBJECT=$PWD/file
```
4) Set targets (BBtargets)
```bash
# Setup directory containing all temporary files
export OUT=$PWD

# Download commit-analysis tool
wget https://raw.githubusercontent.com/jay/showlinenum/develop/showlinenum.awk
chmod +x showlinenum.awk

# Generate BBtargets from commits
pushd $SUBJECT
  git diff -U0 HEAD^ HEAD > $OUT/commit.diff
popd
cat $OUT/commit.diff |  $OUT/showlinenum.awk show_header=0 path=1 | grep -e "\.[ch]:[0-9]*:+" -e "\.cpp:[0-9]*:+" -e "\.cc:[0-9]*:+" | cut -d+ -f1 | rev | cut -c2- | rev > $OUT/BBtargets.txt

# Print extracted targets
echo "Targets:"
cat $OUT/BBtargets.txt
```

5) Instrument subject
```bash
export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++
export CFLAGS="$CFLAGS -distance=$PWD/distance.cfg.txt"
export CXXFLAGS="$CXXFLAGS -distance=$PWD/distance.cfg.txt"


# TO BE CONTINUED ...
```
