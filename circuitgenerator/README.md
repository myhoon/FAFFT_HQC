The `circuitgenerator` directory contains code to find the optimal XOR sequence for binary matrices from $v_{17}$ to $v_{28}$ using the circuit generation method proposed in *Optimizing Implementations of Linear Layers* (Zejun Xiang et al., ToSC 2020). Their original code is at [Optimizing_Implementations_of_Linear_Layers](https://github.com/xiangzejun/Optimizing_Implementations_of_Linear_Layers).

The `make_asm_code` directory includes code that optimizes the generated XOR sequences for the Cortex-M4 environment. An example file `v28.txt` stores the XOR sequence for $v_{28}$, and the code can be run as follows:

```bash
python3 make_asm_code_txt.py v28.txt gft_mul_v28

```

The assembly files for $v_{17}$ through $v_{28}$, generated using the same method, are named gft_mul_vi.s.