# AFLGo: Directed Greybox Fuzzing
<a href="https://comp.nus.edu.sg/~mboehme/paper/CCS17.pdf" target="_blank"><img src="https://comp.nus.edu.sg/~mboehme/paper/CCS17.png" align="right" width="250"></a>
AFLGo is an extension of <a href="https://lcamtuf.coredump.cx/afl/" target="_blank">American Fuzzy Lop (AFL)</a>.
Given a set of target locations (e.g., `folder/file.c:582`), AFLGo generates inputs specifically with the objective to exercise these target locations.

Unlike AFL, AFLGo spends most of its time budget on reaching specific target locations without wasting resources stressing unrelated program components. This is particularly interesting in the context of
* **patch testing** by setting changed statements as targets. When a critical component is changed, we would like to check whether this introduced any vulnerabilities. AFLGo, a fuzzer that can focus on those changes, has a higher chance of exposing the regression.
* **static analysis report verification** by setting statements as targets that a static analysis reports as potentially dangerous or vulnerability-inducing. When assessing the security of a program, static analysis tools might identify dangerous locations, such as critical system calls. AFLGo can generate inputs that actually show that this is indeed no false positive.
* **information flow detection** by setting sensitive sources and sinks as targets. To expose data leakage vulnerabilities, a security researcher would like to generate executions that exercise sensitive sources containing private information and sensitive sinks where data becomes visible to the outside world. A directed fuzzer can be used to generate such executions efficiently.
* **crash reproduction**  by setting method calls in the stack-trace as targets. When in-field crashes are reported, only the stack-trace and some environmental parameters are sent to the in-house development team. To preserve the user's privacy, the specific crashing input is often not available. AFLGo could help the in-house team to swiftly reproduce these crashes.

