# token

Mysterium owned `Sentinel` services issues tokens which can be validated using this `token` package.


### Keys
To generate new public/private key pair for issuer and validator
use nex command:

```ssh-keygen -t rsa -b 4096 -m pem```

To get public key from private key in pem format

```openssl rsa -in id_rsa -pubout -out id_rsa.pub.pem```