# House of Corrosion
## Summary
The House of Corrosion is a heap exploitation technique targeting GLIBC version 2.27.  
Its application against GLIBC 2.29 is described in [Addendum A](#addendum-a).

### The good
* Drop a shell.
* Does not require any leaks.

### The bad
* Requires a write-after-free bug.
* Requires good heap control.

### The ugly
* Requires guessing 4 bits of load address entropy.

### Outline
The House of Corrosion shares similarities with the House of Orange but is updated to work around exploit mitigations introduced between GLIBC 2.23 and 2.27. Use it to drop a shell when the target binary is position-independent and does not leak the addresses of any of its components. It requires being able to write at least 10 bytes of consecutive data via a write-after-free (WAF) bug. Briefly, it works as follows:

* Leverage a WAF bug and guess 4 bits of entropy to direct an unsortedbin attack against the `global_max_fast` variable.
* Combine heap Feng Shui, the WAF bug and fastbin corruption to tamper members of the `stderr` file stream object.
* Trigger `stderr` file stream activity to gain code execution.

## Primitives
The House of Corrosion relies on three primitives provided by corrupting the `global_max_fast` variable via an unsortedbin attack. Once `global_max_fast` has been overwritten with the address of the unsortedbin, large chunks qualify for fastbin insertion when freed. When combined with a WAF bug, this yields three primitives:

### Primitive one
Freeing a large chunk will link it into the “fastbin” for its size, writing the address of that chunk into an offset from the first fastbin. This allows an attacker to overwrite an 8-byte-aligned quadword with a heap address; the target must reside at an address succeeding the first fastbin.

Use the formula: `chunk size = (delta * 2) + 0x20` to calculate the size of a chunk needed to overwrite a target with its address when freed, where delta is the distance between the first fastbin and the target in bytes. This primitive is used in cases where any value other than null, or a writable address is required.

Note that there is [a check](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l4250)
to mitigate this scenario in `_int_free()`, but because `__libc_free()` calls `_int_free()` with a `have_lock` value of 0 it is not performed.

### Primitive two
Using the first primitive, free a large chunk to write its address to an offset from the first fastbin. Because the value at that offset is treated as a fastbin entry, it is copied into the freed chunk’s forward pointer (fd). The fd can be tampered with the WAF bug, then returned to its original location by requesting the same chunk back. This allows an attacker to modify variables in-place or replace them entirely with a new value.

### Primitive three
Build on primitive two to “transplant” a value from one location to another, tampering it in-flight if necessary.

Craft two chunks, “A” and “B”, with sizes that will link them into the “fastbin” overlapping the destination address when freed. Free chunk “B”, then chunk “A”; use the WAF bug to tamper the least-significant byte of chunk “A”’s fd, which points to chunk “B”, and make it point to chunk “A”. Because the sizes of these chunks are large, they must be created on the heap by allocating two small chunks that reside next to each other, then tampering their size fields with the WAF bug.

This requires writing “safe” values to the heap by allocating and freeing chunks. The “safe” values are used to satisfy a check in `_int_free()`; the chunk succeeding the chunk being freed is subject to a [size sanity check](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l4195). This means that freeing a chunk with a modified size field requires a sane size value to be present where the “next” chunk should be. This is achieved by allocating then freeing a chunk so that the top chunk size is written to that location.

Once chunk “A”’s fd has been modified to point to itself, chunk “A” is linked into that “fastbin” twice, the equivalent result of a double-free. Note that this example assumes there is no double-free bug, just a write-after-free. Make a request of the same size to allocate chunk “A”, meaning it can be freed again later but is still linked into the “fastbin” overlapping the destination address.

Leverage the WAF bug again to change the size of chunk “A” to a value that will link it into the “fastbin” overlapping the source address; free it and tamper the value that is copied into the chunk’s fd if required. Using the WAF once more, revert chunk “A”’s size back to the destination value, then request a chunk of that size; the size change must be done to satisfy a [size integrity check](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l3596) in `_int_malloc()`. The result is that a value is “transplanted” from the source address to the destination address and can be tampered along the way. Chunk "A" can be reused in multiple transplants.

## Stages
The House of Corrosion can be broken down into five stages, two of which leverage the primitives outlined above. The description below covers use of this technique against the GLIBC 2.27 version distributed with Ubuntu 18.04 LTS (BuildID **b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0**).

### Stage 1: Heap Feng Shui
* Create “safe” values on the heap by allocating and freeing chunks.
* Allocate and free chunks such that the WAF bug can be used to tamper size fields.
* Sort a chunk into a largebin then tamper its size field.
* Allocate a chunk for use in the unsortedbin attack.
* Allocate chunks for use with primitives one & two.

The “safe” values required by primitive three are written to the heap by allocating and freeing chunks of the appropriate size, creating fake size fields further down the heap.

Leveraging a WAF to tamper size fields can be done in a number of ways, one example could be as follows: allocate a chunk of size n from the top chunk, then allocate a chunk immediately afterwards that can be modified after being freed. Free both of these chunks so that they are consolidated with the top chunk. Allocate a third chunk with size n + 0x10 in the space where the first chunk was, then allocate the last chunk immediately after that. The second quadword of user data belonging to the second chunk overlaps the last chunk’s size field, which can be tampered using the WAF.

Sorting a chunk into a largebin is as simple as freeing a chunk with size 0x420 or larger into the unsortedbin (chunks with size 0x400 and 0x410 will qualify for the tcache in GLIBC 2.27), then requesting a chunk with size larger than 0x420. Use the WAF bug to set the `NON_MAIN_ARENA` bit in this chunk’s size field once it has been sorted into a largebin. This chunk is used in the final stage to trigger `stderr` activity.

Any chunk with size 0x420 or larger will qualify for the unsortedbin in GLIBC 2.27, free a chunk with this size in a position that won’t consolidate it with the top chunk to populate its forward (fd) and backward (bk) pointers. This chunk must be the first chunk in the unsortedbin, meaning that it is the most recent chunk to be placed there; this ensures that its bk holds the address of the head of the unsortedbin.

Chunks of various sizes must be allocated for use with primitives one and two; once stage 2 is complete these chunks are freed and perhaps allocated again to tamper GLIBC variables.

The largest allocation in this stage is usually no more than 0x3b00 bytes.

### Stage 2: Unsortedbin attack
Direct an unsortedbin attack against the `global_max_fast` variable by overwriting the two least-significant bytes of the bk in the chunk set up for this purpose in stage 1, then allocating it back directly from the unsortedbin. The 12 least-significant bits of the bk are static but bits 13 through 16 are subject to ASLR; guessing these 4 bits is necessary but is the only guesswork required for the attack to succeed. Sometimes GLIBC is loaded at an “unlucky” base address, meaning that the gap between the unsortedbin and `global_max_fast` lies over a 16-page boundary, making it impossible to bridge by guessing only 4 bits of entropy.

### Stage 3: Fake unsorted chunk
The last step of the House of Corrosion involves triggering a failed assertion in `_int_malloc()`. This is detailed in stage 5 but involves crafting a size and bk field for the “chunk” pointed to by the unsortedbin bk after the unsortedbin attack. The size field, which overlaps the `dumped_main_arena_start` symbol, is set with primitive two to a value such that this “chunk” qualifies for the same largebin as the chunk with the set `NON_MAIN_ARENA` flag allocated in stage 1. The fake chunk’s bk, which overlaps the `pedantic` symbol, must be a writable address; use primitive one to achieve this.

### Stage 4: Tampering stderr
Using the three primitives, set up the `stderr` file stream for file stream exploitation. This can be achieved in a number of ways, depending on whether the attacker is able to call `exit()` (explicitly or by returning from `main()`), or if there is regular activity on either the `stderr` or `stdout` file streams. Described here is the most restrictive scenario in which the attacker cannot call `exit()` and there is no activity on either the `stderr` or `stdout` file streams. The goal is to call `_IO_str_overflow(stderr)` after modifying the `stderr` file stream.

Note that if there is activity on either file stream, values written to them may be clobbered or cause faults. This can be mitigated by using primitive two to set the `_mode` field of either file stream to a value of 1; this ensures that if a program attempts to write to these streams it will not be successful. Be aware that setting the `stdout` `_mode` field to 1 will stop a program from printing anything to the terminal, although it will still function normally.

#### \_flags
Use primitive two to set the `_flags` field of the `stderr` file stream to zero. This has two purposes: the first is to ensure that three checks in the `_IO_str_overflow()` [function](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/strops.c;h=ac995c830e87e8214d18e381c29cf95f45bfee6b;hb=23158b08a0908f381459f273a984c6fd328363cb#l80) evaluate correctly, the second is to set the `rcx` register to zero before a one-gadget is called later, the constraint for which is that `rcx` is zero. The `rcx` register receives a copy of `_flags` during `_IO_str_overflow()`.

#### \_IO\_write\_ptr
To ensure the correct code path in `_IO_str_overflow()` is followed, the difference between `_IO_write_base` and `_IO_write_ptr` must be greater than the difference between `_IO_buf_base` and `_IO_buf_end`. Since it is necessary to populate both `_IO_buf_base` and `_IO_buf_end`, ensure the difference between `_IO_write_base` and `_IO_write_ptr` is greater by writing a large value to `_IO_write_ptr` with primitive two. If there has been activity on `stderr` and `_IO_write_base` is a large value, setting it to zero can help.

#### \_IO\_buf\_base
The result of calling `_IO_str_overflow` is to redirect execution to one of the plentiful `call rax` gadgets in GLIBC, at that moment the `rax` register is populated with the difference between `_IO_buf_base` and `_IO_buf_end`. Use primitive three to transplant the address of the `__default_morecore()` function from the `__morecore` symbol into the `_IO_buf_end` field. Use primitive two to set `_IO_buf_base` to the delta between `__default_morecore()` and the one-gadget at offset 0x4f2c5. This part is GLIBC build-specific, see the considerations section for more information.

#### \_IO\_buf\_end
If there has been activity on `stderr` this can make things a bit simpler, but assume that this field is null and must be populated with a GLIBC address. As mentioned above, use primitive three to transplant the address of the `__default_morecore()` function from the `__morecore` symbol into the `stderr` `_IO_buf_end` field.

#### vtable
The goal of tampering the `stderr` vtable pointer is to call  the `_IO_str_overflow()` function when `stderr` activity is triggered, to do this use primitive two to tamper the two least-significant bytes of the `stderr` vtable pointer and point it at the `_IO_str_jumps` table - 0x20. This aligns the `_IO_str_overflow()` entry of the `_IO_str_jumps` table with the `__xsputn` vtable offset. Because the 4 bits of load address entropy in the second-to-last byte must have been guessed correctly to get this far, another guess is not necessary.

#### \_s.\_allocate\_buffer
If the above fields were set up correctly, when `_IO_str_overflow()` is called it will in turn call the function pointer at (`_IO_strfile*)stderr._s._allocate_buffer()`. This resides at `stderr + 0xe0`, just after the vtable pointer. This address overlaps the `stdout` `_flags` field; if there is `stdout` activity set the `stdout` `_mode` field to 1 as advised at the beginning of this section. There is no need to return the `stdout` `_mode` field to its original value, when a shell is started via a one-gadget it will use its own `stdout` and `stderr` file streams.

Use primitive three to transplant a GLIBC executable address to this field from the `.data` section, tampering it in-flight to point at a `call rax` gadget. Reusing `__default_morecore()` from the `_IO_buf_end` transplant can save one call to `malloc()`. There must be a `call rax` gadget reachable from the address used here by tampering only its two least-significant bytes, but `call rax` gadgets are plentiful – there are 20 within reach of `__default_morecore()` in the GLIBC version that ships with Ubuntu 18.04 LTS. When searching for these gadgets, ensure that duplicate gadgets aren't being hidden, a common default setting for tools like Ropper.

### Stage 5: Force stderr activity
Under the assumption that there is no `stderr` activity and the attacker cannot exit the program to call `_IO_flush_all_lockp()`, triggering a failed assertion in GLIBC will cause an error message to be printed to `stderr`. Yes, assert statements aren't supposed to make it into production software, but they do. See the [Considerations](#considerations) section for more information. Since this technique involves heap corruption already, the easiest way to do this is to sort a chunk into a largebin in which the first chunk has a set `NON_MAIN_ARENA` flag. This is because `NON_MAIN_ARENA` flags are not set in free chunks other than fast chunks, the flag is only set when a chunk is allocated to a program.

Calls to `malloc_printerr()` do not use the `stderr` file stream, but the file descriptor (fd) instead, and as of GLIBC 2.27 the `abort()` function no longer calls `_IO_flush_all_lockp()`. This is why the fake chunk at `global_max_fast` is populated in stage 3, requesting any size other than the size of this chunk will sort it into the same largebin as the chunk with the `NON_MAIN_ARENA` flag set and fail [the assertion](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l3830).

When the assert statement fails, an error message is printed to `stderr`; triggering `stderr` activity in this way works even if the `stderr` file stream has been closed. The `__xsputn` entry in the `stderr` file stream vtable is called, because the `stderr` vtable pointer was tampered that entry now points to `_IO_str_overflow()`. The various fields that were tampered in the `stderr` file stream coerce `_IO_str_overflow()` to call the `_s._allocate_buffer()` function pointer which resides at `stderr + 0xe0`. This location was populated with the address of a `call rax` gadget; when this gadget is executed the `rax` register holds the difference between the `_IO_buf_end` and `_IO_buf_base` members of `stderr`. These fields were set up so that this difference is the address of the one-gadget with the constraint `rcx == NULL`. Since `rcx` takes the value of the `_flags` member of `stderr` which was set to null, this constraint is fulfilled, and the one-gadget drops a shell.
 
## Considerations
**So you have to guess 4 bits of entropy for this to work?**

Yes, it will only succeed approximately one in sixteen attempts.

**This only works against that one version of GLIBC that ships with Ubuntu 18.04 LTS?**

As described here, yes. Everything up until the one-gadget will work ubiquitously however, including the `call rax` gadget since these are so common. You control the address the `call rax` gadget redirects to, it can be any address within the library ASLR zone so creativity is the only limit. Whether the constraints for the one-gadgets in your version of GLIBC are available depends on the final approach. Substituting `_IO_str_overflow()` with `_IO_str_finish()` for example, yields different register control and stack state, as does getting there via `_IO_flush_all_lockp()` rather than `__assert()`.

**Can’t I just use a tcache dup if I have a WAF bug?**

Tcache dups are great if you’re able to leak the load address of GLIBC or otherwise. The House of Corrosion is best leveraged against PIC binaries that don’t leak anything.

**Why not use primitive three to write a value to the free hook?**

Primitive three requires that a heap address be written to the destination first, which will cause a segfault when `free()` is called, which it must be before the final value can be written.

**How did those assert statements get into production software?**

I'm not sure, all I know is that Ubuntu in particular has some oddities in its GLIBC binaries; the assert statements are still present and some versions (e.g. Ubuntu 19.04) also have a broken libio vtable hardening implementation in which the vtable section is mapped writable.

**What’s a minimal binary this could work against?**

A binary that allows request sizes up to 0x3b00 with around 38 requests total and has a repeatable WAF bug that allows an attacker to write 10 bytes of consecutive data into the first one and a quarter quadwords of a free chunk’s user data. Other than that the binary can be PIC, have full RELRO, NX, stack canaries etc.

**This won’t work in my debugger.**

As mentioned in stage 2, there are “unlucky” GLIBC load addresses that cause the gap between the unsortedbin and `global_max_fast` variable to lie over a 16-page boundary, making it impossible to bridge by guessing only 4 bits of entropy. In the GLIBC 2.27 version that ships with Ubuntu 18.04 LTS, these addresses end in 0x3000 or 0x4000 and GDB by default loads GLIBC at the 0x4000 address. If you’re using the pwntools python library you can use the `libs()` function to cheat a little and grab the GLIBC load address to make things easier whilst debugging.

**My exploit segfaults on a “movaps” instruction before the one-gadget fires.**

The version of GLIBC 2.27 that ships with Ubuntu 18.04 LTS was compiled with GCC 7 series which used `movaps` rather than `movups` instructions in some scenarios. This means that if execution hits one of these instructions that is being used to move a value onto the stack and the stack isn’t 16-byte-aligned, it will segfault. This is why it’s important to use the `call rax` gadget rather than a `jmp rax` gadget, it corrects the stack alignment prior to executing the one-gadget.

**This only works when your thread is attached to the main arena.**

Correct. If you are not operating from the main thread but are able to start new threads then repeatedly starting a new thread and calling malloc once to attach the thread to an arena will eventually attach a thread to the main arena. The number of threads it takes to do this is determined by the number of cores available to the process.

## Credit
Angelboy developed the wonderful [House of Orange technique](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html), in which file stream exploitation is leveraged via an unsortedbin attack. Skysider pointed out in [their blog](https://blog.skysider.top/2018/07/01/house-of-orange-in-glibc-2-24/#more) that leaving un-mangled function pointers lying around is indeed a terrible idea and the [Malloc Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt) taught us that corrupting what was then the `av->max_fast` variable could have dire consequences. david942j developed a great [one-gadget finder](https://github.com/david942j/one_gadget). Zach Riggle maintains the fantastic [pwntools](https://github.com/Gallopsled/pwntools) and [pwndbg](https://github.com/pwndbg/pwndbg) python libraries, which make rapid exploit development prototyping much easier.

## Addendum A
The House of Corrosion technique can also be leveraged against GLIBC version 2.29.  
To do so, two further exploit mitigations must be bypassed:
* More robust integrity checks during unsortedbin removal.
* Replacement of the `_allocate_buffer` and `_free_buffer` function pointers with explicit calls to `malloc()` and `free()`.

The improved unsortedbin integrity checks effectively mitigate the unsortedbin attack, although a similar effect can be achieved via a tcache dup. The removal of the `_allocate_buffer` and `_free_buffer` function pointers necessitates an alternate means of bypassing libio vtable protections; this is achieved using the three primitives. The prerequisites are almost identical to the 2.27 attack, except one more byte of write-after-free control is required, bringing the total to 11 bytes. Described below is an example attack against the GLIBC 2.29 version distributed with Ubuntu 19.04 (BuildID **d561ec515222887a1e004555981169199d841024**).

### Tcache attack
The unsortedbin attack served to write a large value over the `global_max_fast` variable, this can instead be done by leveraging a tcache dup to overlap a chunk with `global_max_fast`. One way of doing this is as follows:

Allocate three adjacent chunks, "A", "B" & "C". Chunks "A" and "B" are the same small size e.g. 0x20 and chunk "C" is any size that qualifies for unsortedbin insertion when freed (0x420 and above). Ensure chunk "C" is protected against consolidation with the top chunk.

Free chunk "C" and sort it into a largebin by requesting a larger chunk (e.g. 0x430); either its fd or bk must point to the head of its largebin, this is achieved by ensuring that one of the following is true about chunk "C":
* It is either the largest or smallest chunk in that largebin and the only chunk of its size.
* If it ties for largest it must have been the first chunk of its size to be linked into that bin.
* If it ties for smallest it must have been the second chunk of its size to be linked into that bin.

Free chunk "B" into the tcache, followed by chunk "A". Use the WAF to modify the least-significant byte of chunk "A"'s fd to point at either the fd or bk of chunk "C", linking chunk "C" into the tcache. This works because there are no size field integrity checks on tcache allocations.

Leverage the WAF again to modify the two least-significant bytes of chunk "C"'s fd (or bk) to point at the `global_max_fast` variable, this requires guessing 4 bits of load address entropy. Allocate chunk "A" by requesting it from the tcache, then request the same size to allocate chunk "C". The next chunk returned after a request for the same size will overlap `global_max_fast`, which can subsequently be tampered.

Setting up a WAF to modify chunk "C"'s size field means it can also be used in the final stage to trigger the failed assertion, saving the need to sort another chunk into a largebin. Ensure that a chunk is freed into the unsortedbin before tampering `global_max_fast`, it will be used later to sort into a largebin and trigger the failed assertion.

### Changes to stderr corruption
Only one field of the `stderr` file stream needs to be modified in this version of the House of Corrosion. Use primitive one to write a heap address over the `stderr` vtable pointer. Request a second chunk such that the first quadword of its user data overlaps the `__sync` entry of the "vtable" on the heap. To achieve this these chunks must overlap, which can be done by requesting a small chunk first and tampering its size field with the WAF bug after requesting the second chunk.

Use primitive one to extract the value at the `DW.ref.__gcc_personality_v0` symbol into the second chunk's fd, making it the `__sync` entry in the `stderr` vtable which now sits on the heap. This symbol resides just after the `stdin` pointer which itself sits after the `_IO_2_1_stdout_` struct. It contains a pointer to `__gcc_personality_v0`, which is used in this example because it is within range of a useful gadget. Modify the two least-significant bytes of the pointer to `__gcc_personality_v0` with the WAF bug to point at the `add rsi, r8; jmp rsi` gadget in libc at offset 0x32c7a, within the `_nl_intern_locale_data()` function. After disabling libio vtable protection this gadget will be executed when the failed assertion triggers `stderr` activity.

### Disabling libio vtable protection
The libio vtable protection improvement from GLIBC 2.27 means that one can no longer write any value to `_dl_open_hook` to disable it. However, using the three primitives to tamper some values related to the libc linkmap and `_rtld_global` struct is enough to convince the `_IO_vtable_check()` [function](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/vtables.c;h=c464c588c4724c3f27d7aacf2202999d623a19cf;hb=56c86f5dd516284558e106d04b92875d5b623b7a#l39) that this copy of libc is not operating from within the default namespace and therefore should not be subject to vtable integrity checks. To clarify, C doesn't have namespaces in the same sense that C++ has namespaces, rather in this case it refers to a [linker namespace](https://sourceware.org/glibc/wiki/LinkerNamespaces).

The `_rtld_global` struct resides in the writable segment of the dynamic linker, ld.so. Using the primitives to tamper values outside of libc is possible because the delta between libc and ld.so (and indeed other shared libraries) is constant on a per-program basis and does not change between runs or reboots. Be aware that these deltas are different depending on whether a binary was started under a debugger or not. The libc-ld delta appears to be the same on bare-metal under Ubuntu 19.04, with values of 0x203000 (started under a debugger) and 0x1ff000 (debugger attached) respectively in a small, CTF-style binary written in C. However slightly different values have been observed in VMs, although they are often no more than one or two pages diverged from the bare-metal values and still have a four-page gap between debugging and attached values.

The `_dl_addr()` [function](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-addr.c;h=9d285d76a728a1c378d9f202e31bdc816e16f665;hb=56c86f5dd516284558e106d04b92875d5b623b7a#l124) is used to find the dynamic shared object (DSO) associated with an address; specifically in this case `_IO_vtable_check()` uses it to find the DSO that it is operating from after the `IO_validate_vtable()` function detects that a file stream's vtable does not reside in the expected region. If `_dl_addr()` returns a DSO with a non-default namespace (an `l_ns` value other than 0), then `_IO_vtable_check()` will not abort. However, there is an assert statement in the `_dl_find_dso_for_object()` [function](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-open.c;h=12a4f8b8539c0becebe6d1fcec508f4cbed913a7;hb=56c86f5dd516284558e106d04b92875d5b623b7a#l161) that checks whether the namespace of the object being returned matches the namespace being searched, meaning that simply tampering the namespace field in the libc linkmap is not an option.

Instead, use primitive one to write a heap address over the `_rtld_global._dl_nns` field; this ensures that if `_dl_find_dso_for_object()` is unable to find the shared object in the first (default) namespace, it will continue searching. There are 15 more namespace slots and if a slot is null then it is ignored and the search continues to the next slot. Use primitive three to transplant the `_rtld_global._dl_ns[0]._ns_loaded` value into the second slot at `_rtld_global._dl_ns[1]._ns_loaded`, then use primitive two to zero the first slot's `_ns_loaded` field. Be aware that reaching across the gap between `main_arena` and `_rtld_global` requires allocating very large chunks; it may be necessary to allocate, free, then allocate a chunk again to ensure the `mp_.mmap_threshold` value is adjusted accordingly.

Use primitive two to set the `l_ns` value (the namespace number) of the libc linkmap to 1. The libc linkmap resides in the writable segment after libc if no other libraries were loaded first, otherwise it resides in the writable segment after that library. Now, when `_dl_find_dso_for_object()` looks for the DSO holding `_IO_vtable_check()` it will skip the default namespace because its `_ns_loaded` field is null and move on to the second namespace since the `_dl_nns` value indicates multiple namespaces are in use. Instead, it will find the matching DSO in namespace 1, that's where the libc linkmap resides after the transplant. `_dl_find_dso_for_object()` will return the libc linkmap, which has an `l_ns` value of 1, matching the namespace being searched. The assert passes and `_IO_vtable_check()` returns without aborting, effectively bypassing libio vtable protection.

### Gadget use
The `__sync` entry in the `stderr` vtable points (after tampering) to an `add rsi, r8; jmp rsi` gadget. In the version of GLIBC distributed with Ubuntu 19.04 the `rsi` register is populated with the address of the libc hash table at the point when the gadget is executed. The `r8` register holds the offset of the last symbol in the hash table (`__wcpcpy`), plus its size (0x26), plus the value of the libc linkmap's `l_addr` field. These values are left over from the `determine_info()` [function](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-addr.c;h=9d285d76a728a1c378d9f202e31bdc816e16f665;hb=56c86f5dd516284558e106d04b92875d5b623b7a#l24) after it has iterated through a DSO's hash table; `determine_info()` is called by `_dl_addr()` just before it returns.

In the version of GLIBC used in this example the offset of `__wcpcpy()` is 0xbb460 and its size is 0x26. Using primitive two to tamper the libc linkmap's `l_addr` field results in a predictable state of the `r8` register once these three values have been added together. The gadget adds the controlled value in `r8` to the address of the libc hash table, then jumps to the resulting address. This provides the same outcome as the GLIBC 2.27 version of the House of Corrosion technique, with the added bonus of the `rdi` register pointing to the `stderr` `_flags` field. Overwriting `_flags` with the string "/bin/sh" using primitive two and redirecting execution to `system()` can be used to drop a shell.

Finally, trigger the failed assertion in the same way as in the 2.27 attack by sorting the chunk in the unsortedbin into the same largebin as the chunk with the set `NON_MAIN_ARENA` flag. This attempts to print to `stderr` and the `__sync` entry in the `stderr` vtable is called with the address of the `stderr` file stream as the first argument. The `stderr` vtable pointer holds a heap address, the `__sync` entry of which overlaps a pointer to a `add rsi, r8; jmp rsi` gadget. The `add rsi, r8` instruction adds a controlled value to the address of the libc hash table, resulting in the address of `system()`. The `_flags` field of `stderr` holds the string "/bin/sh", resulting in a call to `system("/bin/sh")`.

### Libio vtable hardening
It's worth noting that the specific version of GLIBC that ships with Ubuntu 19.04 does not fully implement libio vtable hardening as originally designed. The procedures that check whether a file stream's vtable resides in a specific region of memory are intact, but the vtables themselves are mapped into writable memory. It's unclear whether this is intentional. The reason may be due to how the GLIBC Makerules file [checks](https://sourceware.org/git/?p=glibc.git;a=blob;f=Makerules;h=7e4077ee505d2f786ce529f5c0b2f5645d8247f8;hb=fdfc9260b61d3d72541f18104d24c7bcb0ce5ca2#l554) whether a default linker script should be used.

## References
Libio vtable hardening was introduced in GLIBC 2.24 \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51;hp=64ba17317dc9343f0958755ad04af71ec3da637b)\].

Libio vtable hardening was improved in GLIBC 2.27 \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=8e1472d2c1e25e6eabc2059170731365f6d5b3d1)\].

As of GLIBC 2.27 the `abort()` function no longer flushes file stream buffers \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=91e7cf982d0104f0e71770f5ae8e3faf352dea9f;hp=0c25125780083cbba22ed627756548efe282d1a0)\].

GLIBC 2.28 replaced the `_allocate_buffer` and `_free_buffer` function pointers with explicit calls to `malloc()` and `free()` \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=4e8a6346cd3da2d88bbad745a1769260d36f2783)\].

A `bck->fd == victim` check was introduced to unsortedbin removal in GLIBC 2.28 \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)\].

The unsortedbin was further hardened in GLIBC 2.29 \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)\].


708495fbbf12b56f50d66b0f260c89f571ae2903bf1c45766fe18e453eeb98de
