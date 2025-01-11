# Z Anti-Anti-Debugger

## Build

1. Clone Repository
   ```bash
   git clone --recurse-submodules https://github.com/JavaHammes/Z.git
   ```
2. Build using cmake
   ```bash
   cmake -B build
   cmake --build build --clean-first
   ```

## Execute

```
cd bin
./z
```

## Test

```
cmake --build build --target check
```

## Format

```
cmake --build build --target format
```

## Lint

```
cmake --build build --target lint
```

## Valgrind

```
valgrind --leak-check=full bin/z
```

## Clean

```
cmake --build build --target clean_all
```
