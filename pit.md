Assume a PITless path from C1,C2,... to P. 

~~~ hash-based retrieval

1. C1 is benign and asks for content N from P. D(N) is returned and
cached at each (caching) router on the path. No router on the path
can verify the authenticity of D(N) since no PIT state was saved.

    a. C2 is benign and asks for D(N) with its hash h = H(D(N)). The shared
    router R checks h against the hash of cached D(N). R returns D(N).

    b. C2 is malicious and asks for D(N) with an incorrect hash h' != h.
    The shared router checks h' against the hash of D(N). R forwards the
    interest upstream and does not return D(N).

2. C1 is malicious and asks for content N from malicious P. Poisonied
content D(N)' is returned and cached at every router on the path.
No router on the path can verify its authenticity.
    
    a. C2 is benign and asks for D(N)' with h. The shared router R checks
    h against h'. The check fails, and the interest is forwarded. 

    b. C2 is malicious and asks for D(N)' with h'. The shared router R
    verifies the hash and returns D(N)'.

--> Serving from the cache via *hash restriction* will never penalize 
    benign consumers.

Q: what if h does not include N (i.e., for nameless objects)?
 Doesn't matter. If H is collision resistant, then h will always
 (with overwhelming probability) refer to the same thing. 

~~~ key-based retrieval

1. C1 is benign and asks for N from P with K. D(N) is returned and
cached at every caching router. No router on the path can verify the 
authenticity of D(N) since no PIT state was saved.

    a. C2 is benign and asks for D(N) with K. The shared router
    checks for equality with K and that which is in the content and,
    if valid, attempts to verify the signature of D(N). If valid,
    D(N) is returned and marked valid. If invalid, D(N) is discarded
    and the interest is forwarded.

    b. C2 is malicious and asks for D(N) with K'. The shared router
    checks for equality and finds they don't match. The interest is
    forwarded, but the content is *NOT FLUSHED*.

2a. C1 is malicious and asks for content N from malicious P. Poisoned
content D(N) with KeyId K' and invalid signature is returned and cached 
at every router on the path. No router can verify its authenticity. 

    a. C2 is benign and asks for D(N) with K. The shared router
    checks for equality and it fails. The interest is forwarded.

    b. C2 is malicious and asks for D(N) with K'. The signature
    verification fails, D(N) is discarded, and the interest is forwarded.

2b. C1 is malicious and asks for content N from malicious P. Poisoned
content D(N) with KeyId K and invalid signature is returned and cached 
at every router on the path. No router can verify its authenticity. 

    a. C2 is benign and asks for D(N) with K. The shared router checks
    for equality and it succeeds. The signature verification fails,
    D(N) is discarded, and the interest is forwarded.

    b. Same as above...? (Asking with K' would do nothing.)

--> Case 1: not much different from today...
    Case 2: terribly easy to attack and cause computational DoS on routers
    Case 3: same

    ... caching signed content that is not requested by hash is prone to easy attacks.
    So don't cache signed content that cannot be requested by hash.
    
    How does a router know if something can be requested by hash?... It doesn't. 
    So the better answer is to not cache anything that's signed.

Final outcome: do not cache anything that cannot be verified in O(|M|).

~~~ Pros and cons of the PIT (CCN X NDN)

Pros:
- Allows IKB enforcement
- Forwarding content packets without addresses
- Signals communication failures or congestion via timeouts
- Enables per-packet RTT calculations
- Enables duplicate interest aggregation
- Loop detection (*probabilistic*) (via nonces)

Cons:
- Per-packet state can be easily exhausted.
- Per-packet timers are costly.
- For bidirectional applications, the PIT stores redundant information with the FIB.
