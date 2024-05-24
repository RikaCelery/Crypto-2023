BLOCK_SIZE = 128//8
LOOP = 8


def feistel_encrypt(input_bytes: bytes, key, F):
    output = bytes()
    left_half = input_bytes[BLOCK_SIZE // 2:]
    right_half = input_bytes[:BLOCK_SIZE // 2]

    left_half_output = right_half
    function_output = F(left_half_output, key)  # TODO i need a key generate function
    right_half_output = [pair1 ^ pair2 for pair1, pair2 in zip(left_half, function_output)]

    output += bytes(left_half_output)
    output += bytes(right_half_output)
    return output


def feistel_decrypt(input_bytes: bytes, key, F):
    output = bytes()
    left_half = input_bytes[:BLOCK_SIZE // 2]
    right_half = input_bytes[BLOCK_SIZE // 2:]

    left_half_output = right_half
    function_output = F(left_half_output, key)  # TODO i need a key generate function
    right_half_output = [pair1 ^ pair2 for pair1, pair2 in zip(left_half, function_output)]

    output += bytes(right_half_output)
    output += bytes(left_half_output)
    return output


def exchange(input: bytes):
    a = input[BLOCK_SIZE // 2:]
    a += input[:BLOCK_SIZE // 2]
    return a

def F_function(input_bytes: bytes, key: bytes):
    out = []
    for i in range(len(input_bytes)):
        out.append(input_bytes[i] ^ key[i % len(key)])
    return bytes(out)

def get_bits(num):
    bits = []
    while num > 0:
        bits.append(num & 1)  # 使用位与操作符提取最低位的值
        num >>= 1  # 将数字右移一位
    bits.reverse()  # 将结果反转，使得最高位在最前面
    return bits

class LFSR:
    def __init__(self, tap_positions, seed:bytes):
        self.tap_positions = tap_positions
        self.seed = seed
        self.register = seed
        self._move_length_ = seed.bit_length()-1
        self.debug = False

    def shift_get_bytes(self):
        shift = self.shift()
        return shift.to_bytes((self._move_length_+1+7)//8,"big")
    def reset(self):
        self.register =self.seed
    def shift(self):
        if self.debug:
            print("before: {}".format(get_bits(self.register)))
        feedback = 0
        for position in self.tap_positions:
            feedback ^= (self.register >> position) & 1
        self.register = (self.register >> 1) | (feedback << self._move_length_)
        if self.debug:
            print("after : {}".format(get_bits(self.register)))
            print("--------------")
        return self.register
    

def block_encrypt(block: bytes,lfsr:LFSR):
    assert len(block) == BLOCK_SIZE
    cipher = block
    for n in range(LOOP):
        cipher = feistel_encrypt(cipher, lfsr.shift_get_bytes(), F_function)
    cipher = exchange(cipher)
    return bytes(cipher)


def block_decrypt(block: bytes,lfsr:LFSR):
    msg_ = block
    keys = [lfsr.shift_get_bytes() for _ in range(LOOP)]
    for n in range(LOOP, 0, -1):
        msg_ = feistel_decrypt(msg_, keys[(n - 1) % len(keys)], F_function)
    msg_ = exchange(msg_)
    return bytes(msg_)


def slice_arr(arr, size):
    s = []
    for i in range(0, int(len(arr)) + 1, size):
        c = arr[i:i + size]
        if not len(c) == 0:
            s.append(c)
    return s


def encrypt(message: bytes,key:bytes,tap_positions):
    blocks = slice_arr(message, BLOCK_SIZE)
    encrypted_blocks = bytes()
    tail_fill = 0
    lfsr = LFSR(tap_positions,int.from_bytes(key,"big"))
    for enc_ in blocks:
        if len(enc_) < BLOCK_SIZE:
            tail_fill = BLOCK_SIZE - len(enc_)
            encrypted_blocks += (block_encrypt(enc_.zfill(BLOCK_SIZE),lfsr))
        else:
            encrypted_blocks += (block_encrypt(bytes(enc_),lfsr))
    return encrypted_blocks, tail_fill


def decrypt(message: bytes,key:bytes,tap_positions, tail_fill: int):
    blocks = slice_arr(message, BLOCK_SIZE)
    decrypted_blocks = bytes()
    lfsr = LFSR(tap_positions,int.from_bytes(key,"big"))
    for n in range(len(blocks) - 1):
        decrypted_blocks += block_decrypt(bytes(blocks[n]),lfsr)
    decrypted_blocks += (block_decrypt(blocks[-1],lfsr))[tail_fill:]
    return bytes(decrypted_blocks)


