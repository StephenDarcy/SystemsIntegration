$ORIGIN example.com.
$TTL 123
@   IN SOA ns.example.com. admin.example.com. (
    20211013
    2d
    15m
    2w
    1h
)
@   IN A     10.20.30.40
ns  IN A     10.20.30.40
www IN CNAME example.com.
@   IN NS    ns.example.com.
