# README

Launch docker image:

```
docker run -p 8000:8000 mastrogiovanni/strongholdms:main
```

Create private/public key and return public key:

```
curl localhost:8000/save/client_id/test.snapshot/passphrase
```

client

Read public key:

```
curl localhost:8000/load/client_id/test.snapshot/passphrase
```

