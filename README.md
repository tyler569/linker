
### A simple linker

This project implements a simple ELF toolkit, including rudimentary static linking of relocatable objects (`.o` files) and work-in-progress dynamic linking.

The main purpose of this project is to be the testbed for the kernel modeule loader and userspace dynamic linker of the [nightingale operating system](https://github.com/tyler569/nightingale).

To see what I have in action, the old static linking demo is available in the `static/` folder of this project, to run it, in the folder:
```
make
./link
./demo
```

This demo creates a relocatable object, `mod.o`, and then `./link` resolves its unresolved symbols with the `demo` binary. When run, `demo` loads the object into its address space and calls a function in the object, which in turn calls functions in `demo`.


My dynamic linking work is in the main folder of this repo, to see that you can run
```
make
./link-ng
```

At time of writing, that loads `liblib.so` into memory, updates the global offset table to reflect its loaded location, and calls functions in the library. This will evolve over time as I work on making this project a proper userspace program interperter for nightingale.

