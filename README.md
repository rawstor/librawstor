# Rawstor client library

## TL;DR
```
./autogen.sh
./configure --prefix=${HOME}/local
make
make install
```

## Configure

### Disable liburing

```
./configure --without-liburing
```

This will replace liburing with poll.

### Disable OST

```
./configure --disable-ost
```

This will disable OST integration and replace it with local file backend.

## Testing

```
make test
```
