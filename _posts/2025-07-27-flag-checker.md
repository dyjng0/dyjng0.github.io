---
title: UIUCTF - Flag Checker
date: 2025-07-27
categories:
  - CTF
tags:
  - rev
  - CTF
---

This was a fun CTF, especially because I cleared all of the crypto challenges (granted they were all 50 points). However, I also ended up solving this rev challenge which was more involved than other easy rev challenges--I'm not too familiar with Ghidra, and this had me going through the binary itself to get the information I needed.

## Strings Analysis

Generally, anytime we're given an executable, we can run `strings` to see if the flag is a string contained in the binary. Unfortuantely, the closest thing we get from `strings ./flag_checker` is `sigpwny{}`, so the file is sanatized enough that we're going to have to do some deeper searching using a binary decompiler such as ghidra.

## Initial Ghidra Analysis

After running `flag_checker` through Ghidra, we get the following main function.

```c
undefined8 main(void)

{
  char cVar1;
  long in_FS_OFFSET;
  undefined1 local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  get_input(local_38);
  cVar1 = check_input(local_38);
  if (cVar1 != '\0') {
    puts("PRINTING FLAG: ");
    print_flag(local_38);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From a high level analysis, the code first gets the input via `get_input`, then checks the input with `check_input` and stores the result in `cVar1`. Then, if `cVar1` is not the null character `\0`, the flag prints.

## get_input

If we look closely at `get_input`, we can see exactly what happens when we run the executable.

```c
void get_input(long param_1)

{
  int local_10;
  int local_c;
  
  for (local_10 = 0; local_10 < 8; local_10 = local_10 + 1) {
    printf("> ");
    __isoc99_scanf(&DAT_001020a3,param_1 + (long)local_10 * 4);
  }
  for (local_c = 0; local_c < 8; local_c = local_c + 1) {
    *(uint *)((long)local_c * 4 + param_1) = *(uint *)(param_1 + (long)local_c * 4) % 0xffffff2f;
  }
  return;
}
```

`param_1` is likely a pointer to the start of an array. The first for loop loops 8 times, printing `> ` and prompting some input, then storing the input in the next slot of the array. More specifically, since ints are 4 bytes in C, `param_1 + (long)local_10 * 4` points to the next empty spot in memory.

Then, after all 8 values have been inputed, the second for loop goes through all integers `n` stored in the array and replaces it with with `n % 0xffffff2f`, or `n % 4294967087`.

## check_input

This is where the meat of the rev challenge is. After the inputs have been stored in the array pointed at by `local_38`, the array is called by `check_input`.

```c
undefined8 check_input(long param_1)

{
  int iVar1;
  int local_10;
  
  local_10 = 0;
  while( true ) {
    if (7 < local_10) {
      return 1;
    }
    iVar1 = F(*(undefined4 *)(test_pt + (long)local_10 * 4),
              *(undefined4 *)(param_1 + (long)local_10 * 4),0xffffff2f);
    if (iVar1 != *(int *)(test_ct + (long)local_10 * 4)) break;
    local_10 = local_10 + 1;
  }
  return 0;
}
```

`local_10` is some iterator that after the while loop iterates 7 times, the function returns `1`. Looking back at `main`, we get the flag if `check_input` returns anything other than `\0` (which is also `0`), so this is precisely what we want.

Then, the function `F` is called on respective values in the arrays pointed to by `test_pt`, `param_1`, and the value `0xffffff2f` and stored in `iVar1`. Then, `iVar1` is compared to the value of the same index in the array pointed to by `test_ct`--if they are not equal, the while loop breaks and the function returns `0`. Otherwise, `local_10` increments by 1.

Essentially, we need to ensure that the inputs we stored into `param_1`, which if we remember was the array pointer `local_38`, satisfy the function `F` so that the values are equal to the value stored in the array pointer `test_ct`. Then, what is `F`?

### F

We need to remember that `param_1` is `test_pt`, `param_2` is our input, and `param_3` is `0xffffff2f`.

```c
ulong F(long param_1,ulong param_2,ulong param_3)

{
  undefined8 local_28;
  undefined8 local_18;
  undefined8 local_10;
  
  local_18 = 1;
  local_10 = param_1 % (long)param_3;
  for (local_28 = param_2; 0 < (long)local_28; local_28 = (long)local_28 >> 1) {
    if ((local_28 & 1) != 0) {
      local_18 = (local_18 * local_10) % param_3;
    }
    local_10 = (local_10 * local_10) % param_3;
  }
  return local_18;
}
```

Essentially, what this code is doing is calculating `(param_1 ^ param_2) % param_3` by expressing `param_2` in binary. `local_18` keeps track of the powers of `param_1`, and `local_28` keeps track of the bits of `param_2`, bitwise rightshifting every for loop iteration. If the last bit of `local_28` is `1`, `local_18` is multiplied by `local_10`, which is `param_1` raised to powers of 2. This is confusing, so it's better to do an example.

If we wanted to find `(x ^ 13) % n`, where `param_1 = x`, `param_3 = n`, and `param_2 = 13` this is equivalent to `(x ^ 1101) % n` in binary, which is
$$
x^{2^3 + 2^2 + 2^0} \equiv x^{2^3}\cdot x^{2^2}\cdot x^{2^0} \ \left(\mathrm{mod}\ n\right).
$$
Notice that `1101 & 1 = 1`, so the if statement is true and `local_18` is $x^{2^0} \ \left(\mathrm{mod}\  n\right)$. Then, `local_10` becomes $\left( x^{2^0} \right)^2\equiv x^{2^1} \ \left(\mathrm{mod}\ n\right)$, and `local_28` becomes `0110` after one right shift.

Since `0110 & 1 = 0`, `local_18` doesn't change, but `local_10` becomes $\left( x^{2^1} \right)^2 \equiv x^{2^2} \ \left(\mathrm{mod}\ n\right)$ and `local_28 = 0011`. Since `0011 & 1 = 1`, `local_18` is $x^{2^2}\cdot x^{2^0} \ \left(\mathrm{mod}\ n\right)$, and the pattern continues.

## Discrete Log Problem

Now that we got that out of the way, the issue lies in inputting values so that `test_pt ^ input == test_ct (mod 0xffffff2f)`. In ghidra, we get the following.

{% raw %}
<div style="display: flex; justify-content: center; gap: 20px;">
  <img src="assets/flag-checker/test_pt.png" width="600" alt="test pt in binary">
  <img src="assets/flag-checker/test_ct.png" width="600" alt="test ct in binary">
</div>
{% endraw %}

Again, since there are 4 bytes per int in C, we get that

```c
test_pt = [0x2265b1f5, 0x91b7584a, 0xd8f16adf, 0xcd613e30, 0xc386bbc4, 0x1027c4d1, 0x414c343c, 0x1e2feb89]
test_ct = [0xdc44bf5e, 0x5aff1cec, 0xe1e9b4c2, 0x01329b92, 0x8f9ca92a, 0x0e45c5b4, 0x604a4b91, 0x7081eb59]
```

Now, we solve the discrete log problem.

### Sage Script

Sage has a native discrete log solver, so solving this was relatively simple.

```python
modulus = 0xffffff2f
F = GF(modulus)
test_pt = [F(x) for x in [0x2265b1f5, 0x91b7584a, 0xd8f16adf, 0xcd613e30, 0xc386bbc4, 0x1027c4d1, 0x414c343c, 0x1e2feb89]]
test_ct = [F(x) for x in [0xdc44bf5e, 0x5aff1cec, 0xe1e9b4c2, 0x01329b92, 0x8f9ca92a, 0x0e45c5b4, 0x604a4b91, 0x7081eb59]]

for i in range(len(test_pt)):
    print(discrete_log(test_ct[i], test_pt[i]))
```

This spits out

```
2127877499
1930549411
2028277857
2798570523
901749037
1674216077
3273968005
3294916953
```

and finally, inputting these values into the executable yields

```
> 2127877499
> 1930549411
...
PRINTING FLAG: 
sigpwny{CrackingDiscreteLogs4TheFun/Lols}
```

***

[Download flag-checker](/assets/flag-checker/flag_checker.tar.gz)
