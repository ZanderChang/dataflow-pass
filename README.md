# dataflow pass

A trivial LLVM pass that instruct tainted memory access with [DFSan][dfsan].

## Requirement:

- LLVM 8.0.1
- clang
- compiler-rt (dataflow sanitizer)
- lit (for running test suite)

## Build:

```bash
mkdir build
cd build
cmake ..
make
```
## Simple example

As for target source `example/target.c`
```c
1	#include <string.h>
2	#include "runtime.h"
3	#define MAXSIZE 256
4	int main()
5	{
6	    char src[MAXSIZE] = {1};
7	    char dst[MAXSIZE] = {0};
8	    df_init(src, MAXSIZE);
9	    memcpy(dst, src, MAXSIZE/2);
10	    char temp;
11	    temp = dst[0];
12	    temp = dst[MAXSIZE/2 - 1];
13	    temp = dst[MAXSIZE/2];
14	    df_stat();
15	    return 0;
16	}
```

1) 使用Clang编译`target.c`并插桩，在每一条`Load`（读内存）和`Store`（写内存）指令后分别插入对函数`__loadcheck`和`__storecheck`的调用。`target.c`中手动调用`dfsan_create_label`为`src`创建源标签，这样在后续每次读写内存后，`DFSan`会维护标签的传递情况，因此通过`dfsan_has_label`函数可以得知当前操作的目标指针指向的内容是否被`src`污染（注意`memcpy`被处理为先`Store`后`Load`，而`memset`为`Store`）。

```bash
cd example
clang -g -fsanitize=dataflow -std=c11 -Xclang -load -Xclang ../build/dataflow/libLoadStorePass.so -c target.c -o target.o
```

2) 使用Clang编译`runtime.c`为库，提供插桩时插入函数调用的实现
```bash
clang -g -fsanitize=dataflow runtime.c -c -o runtime.o
```

3) 链接到一起得到`target`
```bash
clang -fsanitize=dataflow target.o runtime.o -o target
```

Sample output of runtime checking:
```text
DF_RUNTIME: N/A:0: clean store 4 byte(s)
DF_RUNTIME: target.c:6: clean store 256 byte(s)
DF_RUNTIME: target.c:6: clean store 1 byte(s)
DF_RUNTIME: target.c:7: clean store 256 byte(s)
DF_RUNTIME: label initialized
DF_RUNTIME: target.c:9: tainted store 128 byte(s)
DF_RUNTIME: target.c:9: tainted load 128 byte(s)
DF_RUNTIME: target.c:11: tainted load 1 byte(s)
DF_RUNTIME: target.c:11: tainted store 1 byte(s)
DF_RUNTIME: target.c:12: tainted load 1 byte(s)
DF_RUNTIME: target.c:12: tainted store 1 byte(s)
DF_RUNTIME: target.c:13: clean load 1 byte(s)
DF_RUNTIME: target.c:13: clean store 1 byte(s)
DF_RUNTIME: total 4 load, 3 tainted, 1 clean
DF_RUNTIME: total 4 store, 3 tainted, 1 clean
```



[dfsan]:https://clang.llvm.org/docs/DataFlowSanitizer.html
