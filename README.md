# House of Corrosion
## Summary
The House of Corrosion is a heap exploitation technique targeting GLIBC version 2.27.

### The good
* Drop a shell.
* Does not require any leaks.

### The bad
* Requires a use-after-free bug.
* Requires good heap control.

### The ugly
* Requires guessing 4 bits of load address entropy.

### Outline
The House of Corrosion shares similarities with the House of Orange but is updated to work around exploit mitigations introduced between GLIBC 2.23 and 2.27. Use it to drop a shell when the target binary is position-independent and does not leak the addresses of any of its components. It requires being able to write at least 10 bytes of consecutive data via a use-after-free (UAF) bug. Briefly, it works as follows:

* Leverage a UAF bug and guess 4 bits of entropy to direct an unsortedbin attack against the global\_max\_fast variable.
* Combine heap Feng Shui, the UAF bug and fastbin corruption to tamper members of the stderr file stream object.
* Trigger stderr file stream activity to gain code execution.

## Primitives
The House of Corrosion relies on three primitives provided by corrupting the global\_max\_fast variable via an unsortedbin attack. Once global\_max\_fast has been overwritten with the address of the unsortedbin, large chunks qualify for fastbin insertion when freed. When combined with a UAF bug, this yields three primitives:

### Primitive one
Freeing a large chunk will link it into the “fastbin” for its size, writing the address of that chunk into an offset from the first fastbin. This allows an attacker to overwrite an 8-byte-aligned quadword with a heap address; the target must reside at an address succeeding the first fastbin.

Use the formula: chunk size = (delta \* 2) + 0x20 to calculate the size of a chunk needed to overwrite a target with its address when freed, where delta is the distance between the first fastbin and the target in bytes. This primitive is used in cases where any value other than null, or a writable address is required.

Note that there is [a check](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l4250)
to mitigate this scenario in \_int\_free(), but because \_\_libc\_free() calls \_int\_free() with a have\_lock value of 0 it is not performed.

### Primitive two
Using the first primitive, free a large chunk to write its address to an offset from the first fastbin. Because the value at that offset is treated as a fastbin entry, it is copied into the freed chunk’s fd. The fd can be tampered with the UAF bug, then returned to its original location by requesting the same chunk back. This allows an attacker to modify variables in-place or replace them entirely with a new value.

### Primitive three
Build on primitive two to “transplant” a value from one location to another, tampering it in-flight if necessary.

Craft two chunks, “A” and “B”, with sizes that will link them into the “fastbin” overlapping the destination address when freed. Free chunk “B”, then chunk “A”; use the UAF bug to tamper the least-significant byte of chunk “A”’s fd, which points to chunk “B”, and make it point to chunk “A”. Because the sizes of these chunks are large, they must be created on the heap by allocating two small chunks that reside next to each other, then tampering their size fields with the UAF bug.

This requires writing “safe” values to the heap by allocating and freeing chunks. The “safe” values are used to satisfy a check in \_int\_free(); the chunk succeeding the chunk being freed is subject to a [size sanity check](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l4195). This means that freeing a chunk with a modified size field requires a sane size value to be present where the “next” chunk should be. This is achieved by allocating then freeing a chunk so that the top chunk size is written to that location.

Once chunk “A”’s fd has been modified to point to itself, chunk “A” is linked into that “fastbin” twice, the equivalent result of a double-free. Make a request of the same size to allocate chunk “A”, meaning it can be freed again later but is still linked into the “fastbin” overlapping the destination address.

Leverage the UAF bug again to change the size of chunk “A” to a value that will link it into the “fastbin” overlapping the source address; free it and tamper the value that is copied into the chunk’s fd if required. Using the UAF once more, revert chunk “A”’s size back to the destination value, then request a chunk of that size; the size change must be done to satisfy a [size integrity check](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l3596) in \_int\_malloc(). The result is that a value is “transplanted” from the source address to the destination address and can be tampered along the way.

## Stages
The House of Corrosion can be broken down into five stages, two of which leverage the primitives outlined above. The description below covers use of this technique against the GLIBC 2.27 version distributed with Ubuntu 18.04 LTS (BuildID **b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0**).

### Stage 1: Heap Feng Shui
* Create “safe” values on the heap by allocating and freeing chunks.
* Allocate and free chunks such that the UAF bug can be used to tamper size fields.
* Sort a chunk into a largebin then tamper its size field.
* Allocate a chunk for use in the unsortedbin attack.
* Allocate chunks for use with primitives one & two.

The “safe” values required by primitive three are written to the heap by allocating and freeing chunks of the appropriate size, creating fake size fields further down the heap.

Leveraging a UAF to tamper size fields can be done in a number of ways, one example could be as follows: allocate a chunk of size n from the top chunk, then allocate a chunk immediately afterwards that can be modified after being freed. Free both of these chunks so that they are consolidated with the top chunk. Allocate a third chunk with size n + 0x10 in the space where the first chunk was, then allocate the last chunk immediately after that. The second quadword of user data belonging to the second chunk overlaps the last chunk’s size field, which can be tampered using the UAF.

Sorting a chunk into a largebin is as simple as freeing a chunk with size 0x420 or larger into the unsortedbin (chunks with size 0x400 and 0x410 will qualify for the tcache in GLIBC 2.27), then requesting a chunk with size larger than 0x420. Use the UAF bug to set the NON\_MAIN\_ARENA bit in this chunk’s size field once it has been sorted into a largebin. This chunk is used in the final stage to trigger stderr activity.

Any chunk with size 0x420 or larger will qualify for the unsortedbin in GLIBC 2.27, free a chunk with this size in a position that won’t consolidate it with the top chunk to populate its forward (fd) and backward (bk) pointers. This chunk must be the first chunk in the unsortedbin, meaning that it is the most recent chunk to be placed there; this ensures that its bk holds the address of the head of the unsortedbin.

Chunks of various sizes must be allocated for use with primitives one & two; once stage 2 is complete these chunks are freed and perhaps allocated again to tamper GLIBC variables.

The largest allocation in this stage is usually no more than 0x3b00 bytes.

### Stage 2: Unsortedbin attack
Direct an unsortedbin attack against the global\_max\_fast variable by overwriting the two least-significant bytes of the bk in the chunk set up for this purpose in stage 1, then allocating it back directly from the unsortedbin. The 12 least-significant bits of the bk are static but bits 13 through 16 are subject to ASLR; guessing these 4 bits is necessary but is the only guesswork required for the attack to succeed. Sometimes GLIBC is loaded at an “unlucky” base address, meaning that the gap between the unsortedbin and global\_max\_fast lies over a 16-page boundary, making it impossible to bridge by guessing only 4 bits of entropy.

### Stage 3: Fake unsorted chunk
The last step of the House of Corrosion involves triggering a failed assertion in \_int\_malloc(). This is detailed in stage 5 but involves crafting a size and bk field for the “chunk” pointed to by the unsortedbin bk after the unsortedbin attack. The size field, which overlaps the dumped\_main\_arena\_start symbol, is set with primitive two to a value such that this “chunk” qualifies for the same largebin as the chunk with the set NON\_MAIN\_ARENA flag allocated in stage 1. The fake chunk’s bk, which overlaps the pedantic symbol, must be a writable address; use primitive one to achieve this.

### Stage 4: Tampering stderr
Using the three primitives, set up the stderr file stream for file stream exploitation. This can be achieved in a number of ways, depending on whether the attacker is able to call exit() (explicitly or by returning from main()), or if there is regular activity on either the stderr or stdout file streams. Described here is the most restrictive scenario in which the attacker cannot call exit() and there is no activity on either the stderr or stdout file streams. The goal is to call \_IO\_str\_overflow(stderr) after modifying the stderr file stream.

Note that if there is activity on either file stream, values written to them may be clobbered or cause faults. This can be mitigated by using primitive two to set the \_mode field of either file stream to a value of 1; this ensures that if a program attempts to write to these streams it will not be successful. Be aware that setting the stdout \_mode field to 1 will stop a program from printing anything to the terminal, although it will still function normally.

#### \_flags
Use primitive two to set the \_flags field of the stderr file stream to zero. This has two purposes: the first is to ensure that three checks in the \_IO\_str\_overflow [function](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/strops.c;h=ac995c830e87e8214d18e381c29cf95f45bfee6b;hb=23158b08a0908f381459f273a984c6fd328363cb#l80) evaluate correctly, the second is to set the rcx register to zero before a one-gadget is called later, the constraint for which is that rcx is zero. The rcx register receives a copy of \_flags during \_IO\_str\_overflow().

#### \_IO\_write\_ptr
To ensure the correct code path in \_IO\_str\_overflow() is followed, the difference between \_IO\_write\_base and \_IO\_write\_ptr must be greater than the difference between \_IO\_buf\_base and \_IO\_buf\_end. Since it is necessary to populate both \_IO\_buf\_base and \_IO\_buf\_end, ensure the difference between \_IO\_write\_base and \_IO\_write\_ptr is greater by writing a large value to \_IO\_write\_ptr with primitive two. If there has been activity on stderr and \_IO\_write\_base is a large value, setting it to zero can help.

#### \_IO\_buf\_base
The result of calling \_IO\_str\_overflow is to redirect execution to one of the plentiful “call rax” gadgets in GLIBC, at that moment the rax register is populated with the difference between \_IO\_buf\_base and \_IO\_buf\_end. Use primitive three to transplant the address of the \_\_default\_morecore() function from the \_\_morecore symbol into the \_IO\_buf\_end field. Use primitive two to set \_IO\_buf\_base to the delta between \_\_default\_morecore() and the one-gadget at offset 0x4f2c5. This part is GLIBC build-specific, see the considerations section for more information.

#### \_IO\_buf\_end
If there has been activity on stderr this can make things a bit simpler, but assume that this field is null and must be populated with a GLIBC address. As mentioned above, use primitive three to transplant the address of the \_\_default\_morecore() function from the \_\_morecore symbol into the stderr \_IO\_buf\_end field.

#### vtable
The goal of tampering the stderr vtable is to call  the \_IO\_str\_overflow() function when stderr activity is triggered, to do this use primitive two to tamper the two least-significant bytes of the stderr vtable and point it at the \_IO\_str\_jumps table - 0x20. This aligns the \_IO\_str\_overflow() entry of the \_IO\_str\_jumps table with the \_\_xsputn vtable offset. Because the 4 bits of load address entropy in the second-to-last byte must have been guessed correctly to get this far, another guess is not necessary.

#### \_s.\_allocate\_buffer
If the above fields were set up correctly, when \_IO\_str\_overflow() is called it will in turn call the function pointer at (\_IO\_strfile\*)stderr.\_s.\_allocate\_buffer(). This resides at stderr + 0xe0, just after the vtable pointer. This address overlaps the stdout \_flags field; if there is stdout activity set the stdout \_mode field to 1 as advised at the beginning of this section. There is no need to return the stdout \_mode field to its original value, when a shell is started via a one-gadget it will use its own stdout and stderr file streams.

Use primitive three to transplant a GLIBC executable address to this field from the .data section, tampering it in-flight to point at a “call rax” gadget. Reusing \_\_default\_morecore() from the \_IO\_buf\_end transplant can save one call to malloc(). There must be a “call rax” gadget reachable from the address used here by tampering only its two least-significant bytes, but “call rax” gadgets are plentiful – there are 20 within reach of \_\_default\_morecore() in the GLIBC version that ships with Ubuntu 18.04 LTS.

### Stage 5: Force stderr activity
Under the assumption that there is no stderr activity and the attacker cannot exit the program to call \_IO\_flush\_all\_lockp(), triggering a failed assertion in GLIBC will cause an error message to be printed to stderr. Since this technique involves heap corruption already, the easiest way to do this is to sort a chunk into a largebin in which the first chunk has a set NON\_MAIN\_ARENA flag. This is because NON\_MAIN\_ARENA flags are not set in free chunks other than fast chunks, the flag is only set when a chunk is allocated to a program.

Calls to malloc\_printerr() do not use the stderr file stream, but the file descriptor (fd) instead, and as of GLIBC 2.27 the abort() function no longer calls \_IO\_flush\_all\_lockp(). This is why the fake chunk at global\_max\_fast is populated in stage 3, requesting any size other than the size of this chunk will sort it into the same largebin as the chunk with the NON\_MAIN\_ARENA flag set and fail [the assertion](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l3830).

When the assert statement fails, an error message is printed to stderr. The \_\_xsputn entry in the stderr file stream vtable is called, because the stderr vtable was tampered that entry now points to \_IO\_str\_overflow(). The various fields that were tampered in the stderr file stream coerce \_IO\_str\_overflow() to call the \_s.\_allocate\_buffer() function pointer which resides at stderr + 0xe0. This location was populated with the address of a “call rax” gadget; when this gadget is executed the rax register holds the difference between the \_IO\_buf\_end and \_IO\_buf\_base members of stderr. These fields were set up so that this difference is the address of the one-gadget with the constraint “rcx == NULL”. Since rcx takes the value of the \_flags member of stderr which was set to null, this constraint is fulfilled, and the one-gadget drops a shell.
 
## Considerations
**So you have to guess 4 bits of entropy for this to work?**

Yes, it will only succeed approximately one in sixteen attempts.

**This only works against that one version of GLIBC that ships with Ubuntu 18.04 LTS?**

As described here, yes. Everything up until the one-gadget will work ubiquitously however, including the “call rax” gadget since these are so common. You control the address the “call rax” gadget redirects to, it can be any address within the library ASLR zone so creativity is the only limit. Whether the constraints for the one-gadgets in your version of GLIBC are available depends on the final approach. Substituting \_IO\_str\_overflow() with \_IO\_str\_finish() for example, yields different register control and stack state, as does getting there via \_IO\_flush\_all\_lockp() rather than \_\_assert(). Under one library compiled with GCC 8 series there is an “add rax, [rbx]; call rax” gadget in ld.so which can be used when rbx holds a copy of \_flags. If you can control the rdi register which is also possible with some approaches, calling system(“/bin/sh”) is a safer option.

**Can’t I just use a tcache dup if I have a UAF bug?**

Tcache dups are great if you’re able to leak the load address of GLIBC or otherwise. The House of Corrosion is best leveraged against PIC binaries that don’t leak anything.

**Why not use primitive three to write a value to the free hook?**

Primitive three requires that a heap address be written to the destination first, which will cause a segfault when free is called, which it must be before the final value can be written.

**What’s a minimal binary this could work against?**

A binary that allows request sizes up to 0x3b00 with around 38 requests total and has a repeatable UAF bug that allows an attacker to write 10 bytes of consecutive data into the first one and a half quadwords of a free chunk’s user data. Other than that the binary can be PIC, have full RELRO, NX, stack canaries etc.

**Could I build a fake file stream on the heap instead?**

If you have the heap control to do so then that could work, although you’ll need to tamper the stderr pointer rather than \_IO\_list\_all if you can’t call \_IO\_flush\_all\_lockp(), which is only possible if there is no stderr activity.

When it comes to crafting your own vtable on the heap, GLIBC version 2.27 introduced a more robust libio vtable check; writing a value to the \_dl\_open\_hook function pointer no longer disables libio vtable checking. It can still be disabled using primitives one and two however, by tampering members of the rtld\_global struct, the libc linkmap, \_\_exit\_funcs and crafting a fake linkmap on the heap. Fake linkmaps are arduous to craft with this technique though.

**This won’t work in my debugger.**

As mentioned in stage 2, there are “unlucky” GLIBC load addresses that cause the gap between the unsortedbin and global\_max\_fast variable to lie over a 16-page boundary, making it impossible to bridge by guessing only 4 bits of entropy. In the GLIBC 2.27 version that ships with Ubuntu 18.04 LTS, these addresses end in 0x3000 or 0x4000 and GDB by default loads GLIBC at the 0x4000 address. If you’re using the pwntools python library you can use the libs() function to cheat a little and grab the GLIBC load address to make things easier whilst debugging.

**My exploit segfaults on a “movaps” instruction before the one-gadget fires.**

The version of GLIBC 2.27 that ships with Ubuntu 18.04 LTS was compiled with GCC 7 series which used “movaps” rather than “movups” instructions in some scenarios. This means that if execution hits one of these instructions that is being used to move a value onto the stack and the stack isn’t 16-byte-aligned, it will segfault. This is why it’s important to use the “call rax” gadget rather than a “jmp rax” gadget, it corrects the stack alignment prior to executing the one-gadget.

## Credit
Angelboy developed the wonderful [House of Orange technique](http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html), in which file stream exploitation is leveraged via an unsortedbin attack. Skysider pointed out in [their blog](https://blog.skysider.top/2018/07/01/house-of-orange-in-glibc-2-24/#more) that leaving un-mangled function pointers lying around is indeed a terrible idea and the [Malloc Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt) taught us that corrupting what was then the av->max\_fast variable could have dire consequences. david942j developed a great [one-gadget finder](https://github.com/david942j/one_gadget). Zach Riggle maintains the fantastic [pwntools](https://github.com/Gallopsled/pwntools) and [pwndbg](https://github.com/pwndbg/pwndbg) python libraries, which make rapid exploit development prototyping much easier.

## References
As of GLIBC 2.27 the abort() function no longer flushes file stream buffers \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=91e7cf982d0104f0e71770f5ae8e3faf352dea9f;hp=0c25125780083cbba22ed627756548efe282d1a0)\].

Libio vtable hardening was introduced in GLIBC 2.24 \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51;hp=64ba17317dc9343f0958755ad04af71ec3da637b)\].

Libio vtable hardening was improved in GLIBC 2.27 \[[commit](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=8e1472d2c1e25e6eabc2059170731365f6d5b3d1)\].

708495fbbf12b56f50d66b0f260c89f571ae2903bf1c45766fe18e453eeb98de
