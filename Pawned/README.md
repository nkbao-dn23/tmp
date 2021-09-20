# Problem

```sh
Author: @M_alpha#3534

Welcome to our pawn shop. Only used items are allowed.

Download the files below and press the Start button on the top-right to begin this challenge.
Connect with:
nc challenge.ctf.games 32545
Attachments: [pawned] [libc-2.31.so]
```

# Solution
- Almost Full protection.  

<img src="tmp/checksec.png">

- In `buy_item` function, `free` but do not set the place where that heap address stored to Zero --> **Double Free**. But After `libc2.29` was updated, now it's `libc-2.31`, it make `double free attack` harder to exploit. Find another `vulnerability`.  

<img src="tmp/vuln1.png">

- In `manage_items`, we can edit used items and **freed item** because of the `previous vulnerability` --> **Used After Free**

- The plan is:
	+ Leak libc_base: create 2 big chunks, free them, use `print_items` function to leak `libc address` via `main_arena+96`
	+ Overwrite **__free_hook** by `system` (`one_gadget` not work in both `__malloc_hook` and `__free_hook`): Create 2 chunks (1, 2) with the same and small size, free(1) free(2). Now using `print_items` to edit chunk2 with address point to `__free_hook`. Create a chunk with the same size as privious 2 chunks, pass a string "/bin/sh\x00", so when free, it goes to `__free_hook` execute `system` with that address as argument. Create a last chunk with same size, now `malloc` return us to `__free_hook`, pass address of `system` in there. Next time, just free a chunk having the string "/bin/sh\x00" -> we get shell.  

<img src="tmp/mallocfree.png">

- Well that's all and we can get the flag, you can find the script [here](solve/solve.py)

<img src="tmp/flag.png">


## Thanks for reading :xD