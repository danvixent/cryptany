# cryptany

A simple tool for encrypting any sequence of bytes using a key

Use the following command to install it into your GOPATH

```shell
    go install github.com/danvixent/cryptany
```

## Examples

For encryption:

```bash
    $ cryptany -path /path/to/file -key somekey -enc
        encrypted file: /path/to/file.crypt
```

For decryption:

```bash
    $ cryptany -path /path/to/file.crypt -key somekey -dec
        decrypted file: /path/to/file
```

Specifying custom output directory:

```bash
    $ cryptany -path /path/to/file -key somekey -enc -out ~/crypts
        encrypted file: ~/crypts/file.crypt
```
