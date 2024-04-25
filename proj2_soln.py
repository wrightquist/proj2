import uva_rsa
import secrets
import time
import random
import numpy as np
import statistics


###########################################################
# Problem 1: 6-bit Prefix
# Recover the first 6 bits of the secret key
###########################################################

# mocking oracle
def mod_exp(base, exponent, modulus):
    bits = format(exponent, 'b')
    y = 1
    for b in bits:
        y = (y * y) % modulus
        if '1' == b:
            y = (y * base) % modulus
    return y


def mod_exp_bin(base, bits, modulus):
    y = 1
    for b in bits:
        y = (y * y) % modulus
        if '1' == b:
            y = (y * base) % modulus
    return y


class SixBitOracleDecrypt:
    __d, __n = 0, 0

    def __init__(self, d, n):
        self.__n = n
        self.__d = d

    def run_6bits(self, ct):
        mod_exp(ct, self.__d, self.__n)


def problem1(pub_e, pub_n, oracle):
    mock_oracles = [SixBitOracleDecrypt(x, pub_n) for x in range(0x00, 0x40)]
    times = [0.0 for _ in range(0x00, 0x40)]

    ct = uva_rsa.rsa_enc(pub_e, pub_n, random.getrandbits(2048))
    reps = 10000
    start = time.perf_counter_ns()
    for _ in range(reps):
        oracle.run_6bits(ct)
    end = time.perf_counter_ns()
    real_time = (end - start) / reps
    for i in range(len(times)):
        reps = 2000
        start = time.perf_counter_ns()
        for _ in range(reps):
            mock_oracles[i].run_6bits(ct)
        end = time.perf_counter_ns()
        times[i] = abs(real_time - ((end - start) / reps))
    min_time = min(times)
    min_indexes = [ind for ind, ele in enumerate(times) if ele == min_time]
    result = random.choice(min_indexes)
    return result


###########################################################
# Problem 2: 3-bit Prefix (continued)
# Recover the first 3 bits of the secret key
########################################################### 
def problem2(pub_e, pub_n, oracle):
    # times = {"000": 0.0, "001": 0.0, "010": 0.0, "011": 0.0, "100": 0.0, "101": 0.0, "110": 0.0, "111": 0.0}
    times = {"0000": 0.0, "0001": 0.0, "00000": 0.0, "00001": 0.0, "000": 0.0, "001": 0.0, "010": 0.0, "011": 0.0}
    reps = 120
    cts = [random.getrandbits(2048) for _ in range(reps)]
    start = time.perf_counter_ns()
    for i in range(reps):
        oracle.run(cts[i])
    end = time.perf_counter_ns()
    real_time = ((end - start) / reps)
    reps = reps // 2
    for k in times:
        keys = [int(k + format(random.getrandbits(2048 - len(k)), 'b'), 2) for x in range(reps)]
        start = time.perf_counter_ns()
        for i in range(len(keys)):
            mod_exp(cts[i], keys[i], pub_n)
        end = time.perf_counter_ns()
        times[k] = abs(real_time - ((end - start) / len(keys)))
    result = min(times, key=times.get)
    print(times)
    indexes = [ky for ky in times.keys() if times[ky] == times[result]]
    result = random.choice(indexes)
    print(result)
    return int(result, 2)


###########################################################
# Problem 3: The whole 2048 bits
# Recover the (roughly) 2048 bits of the secret key
###########################################################
def problem_3_attempt_2(pub_e, pub_n, oracle):
    sk = ""
    samples = 50
    chunk_size = 2
    chunks = [format(x, 'b').zfill(chunk_size) for x in range(pow(2, chunk_size))]
    ciphertexts = [uva_rsa.rsa_enc(pub_e, pub_n, random.getrandbits(2048)) for _ in range(samples)]
    real_times = [0.0 for _ in range(len(ciphertexts))]
    prev_modexp_results = [ciphertexts[i] for i in range(len(ciphertexts))]
    prev_cumulative_time = [0.0 for _ in range(len(ciphertexts))]
    variances = [0.0 for _ in range(2048)]
    for i in range(len(ciphertexts)):
        ct = ciphertexts[i]
        reps = 8
        start = time.perf_counter_ns()
        for k in range(reps):
            oracle.run(ct)
        end = time.perf_counter_ns()
        real_times[i] = (end - start) / reps
    for i in range(2048 // chunk_size):
        time_diffs = [[0.0 for _ in range(len(ciphertexts))] for _ in range(len(chunks))]
        measured_times = [[0.0 for _ in range(len(ciphertexts))] for _ in range(len(chunks))]
        results = [[0 for _ in range(len(ciphertexts))] for _ in range(len(chunks))]
        for c in range(len(ciphertexts)):
            ct = prev_modexp_results[c]
            keys = [chunks[x] for x in range(len(chunks))]
            for ch in range(len(chunks)):
                reps = 1000
                start = time.perf_counter_ns()
                for k in range(reps):
                    mod_exp_bin(ct, keys[ch], pub_n)
                end = time.perf_counter_ns()
                measured_time = (end - start) / reps + prev_cumulative_time[c]
                measured_times[ch][c] = measured_time
                results[ch][c] = mod_exp_bin(ct, keys[ch], pub_n)
                time_diffs[ch][c] = real_times[c] - measured_time
        vars = [statistics.variance(time_diffs[x]) for x in range(len(chunks))]
        # if variance increased unexpectedly, do error correction
        min_var_index = vars.index(min(vars))
        variances[i] = vars[min_var_index]
        prev_cumulative_time = measured_times[min_var_index]
        prev_modexp_results = results[min_var_index]
        sk += chunks[min_var_index]


###########################################################
# Some examples and test cases.
# You shall write your own tests, but you do not need to
# submit them (only the above three functions are graded).
########################################################### 
if __name__ == '__main__':
    # A sample key, 2048-bits
    key1 = {"e": 65537,
            "n": 26334846008439167556765994336545761339068098619101850421771908459419918602128141355234077943248935530058859245371916765929458717691408496374069803243864206525054456891054239459424634162712907872176687992073038190824711743119057398524481757063408686486317239808826593650469866307923539528308953119230902384306178943542441126686061578352279102334653866502920311536313397546287885026738627086034614799371467801646963827587890747711299932470791488642354928910842955461742067813873505900679667440625963269380243732319252322289624537679679000548719937080897079171234468074929759669376046003568677119493377927698383184444971,
            "d": 4150452954516788305322334373505934224092414147025341858259381425646659178605691706486212654370727684626846117494529293210823262969746501329504015330861438248564932422166878714870792714969678806278402238259157411843640134215067682273010431589510827287426792759999212883054785908980030403151122652491713875272966953950697706468122810899702465849201975767642644740088526762001961677935216877828845320587721250185528209814840248616253000685484141272453417580384407258920262649904440074465914446977660642607238586680208905768616792883391776390693711645020742189552372320510460581645319646313943217496379479242398240521369}
    # Random key generation, 2048-bits:
    key = uva_rsa.rsa_gen()
    # key = key1
    print(format(key['d'], 'b').zfill(2048))

    # Problem 1
    print("Problem 1:")
    oracle = uva_rsa.DecryptOracleA(key["d"], key["n"])
    if problem1(key["e"], key["n"], oracle) == uva_rsa.prefix(key["d"], 6):
        print("Problem 1 correct")

    """# problem 2
    print("Problem 2:")
    oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
    if problem2(key["e"], key["n"], oracle) == uva_rsa.prefix(key["d"], 3):
        print("Problem 2 correct")"""

"""# Problem 3
 print("Problem 3:")
 print(format(key1['d'], 'b'))
 oracle = uva_rsa.DecryptOracleB(key["d"], key["n"])
 if problem_3_attempt_2(key["e"], key["n"], oracle) == key["d"]:
     print("Problem 3 correct")"""
