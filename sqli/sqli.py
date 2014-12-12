class BooleanBased:
    # The template of payload, replacing the variable $cond to real condition.
    payload = ""
    # The template of condition, replacing the variable $index and $guess.
    condition = ""
    # The response of query if the condition is true.
    response = ""
    send_payload = None

    def __init__(self, payload, condition, response, send_payload = None):
        self.payload = payload
        self.condition = condition
        self.response = response
        # We can overwrite the function to send payload to target.
        if send_payload != None:
            self.send_payload = send_payload
    
    def binsearch(self, a, b, index = None, num = False): 
        orig_cond = self.condition
        if index != None:
            self.condition = self.condition.replace("$index", str(index))

        while b > a:
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
            buf = self.send_payload(payload)
            if self.response in buf:
                a = mid
            else:
                b = mid

        self.condition = orig_cond
        return mid

    def guess_text(self, length, verbose = False):
        text = ""
        for i in range(length):
            text += chr(self.binsearch(0x20, 0x80, index = i+1))
            if verbose:
                print ("index %3d: " + text) % (i+1)

        return text
