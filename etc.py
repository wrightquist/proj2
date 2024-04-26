def problem1_etc(pub_e, pub_n, oracle):
    mock_oracles = [SixBitOracleDecrypt(x, pub_n) for x in range(0x00, 0x40)]
    times = [0.0 for _ in range(0x00, 0x40)]

    cts = [uva_rsa.rsa_enc(pub_e, pub_n, random.getrandbits(2048)) for _ in range(1)]
    real_times = [0.0 for _ in range(len(cts))]
    for c in range(len(cts)):
        reps = 1000
        start = time.perf_counter_ns()
        for _ in range(reps):
            oracle.run_6bits(cts[c])
        end = time.perf_counter_ns()
        real_times[c] = (end - start) / reps
    for i in range(len(mock_oracles)):
        measured_time_dif = 0
        for c in range(len(cts)):
            reps = 1000
            start = time.perf_counter_ns()
            for _ in range(reps):
                mock_oracles[i].run_6bits(cts[c])
            end = time.perf_counter_ns()
            measured_time_dif += abs(real_times[c] - ((end - start) / reps))
        times[i] = measured_time_dif/len(cts)
    print(times.index(min(times)))
    return times.index(min(times))


def problem3(pub_e, pub_n, oracle):
    sk = ""
    samples = 20
    reps = 4
    chunk_size = 2
    chunks = [format(x, 'b').zfill(chunk_size) for x in range(pow(2, chunk_size))]
    ciphertexts = [random.getrandbits(2048) for _ in range(samples)]
    real_times = [0.0 for _ in range(len(ciphertexts))]
    variances = [0.0 for _ in range(2048)]
    variances_unused = [0.0 for _ in range(2048)]
    for i in range(len(ciphertexts)):
        ct = ciphertexts[i]
        start = time.perf_counter_ns()
        for k in range(reps):
            oracle.run(ct)
        end = time.perf_counter_ns()
        real_times[i] = (end - start) / reps
    for i in range(2048//chunk_size):
        time_diffs = [[0.0 for _ in range(len(ciphertexts))] for _ in range(len(chunks))]
        for c in range(len(ciphertexts)):
            ct = ciphertexts[c]
            keys = [sk+chunks[x]+"".zfill(2048-len(sk)-chunk_size) for x in range(len(chunks))]
            for ch in range(len(chunks)):
                start = time.perf_counter_ns()
                for k in range(reps):
                    mod_exp_bin(ct, keys[ch], pub_n)
                end = time.perf_counter_ns()
                print(f"{end-start}, {ch}, {c}, {i} {sk}{chunks[ch]}")
                time_diffs[ch][c] = real_times[c]-(end-start)/reps
        vars = [statistics.variance(time_diffs[x]) for x in range(len(chunks))]
        min_var_index = vars.index(min(vars))
        variances[i] = vars[min_var_index]
        sk += chunks[min_var_index]
        # if variance increased unexpectedly, do error correction

    return int(sk, 2)




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


def problem2(pub_e, pub_n, oracle):
    # prefix_probs = [0.62, 0.22, 0.14, 0.02]
    prefix_probs = [0.62, 0.22]
    # keys = [uva_rsa.rsa_gen() for _ in range(100)]
    keys = random_keys
    mock_oracles: list[list[FullOracleDecrypt]] = [[], []]
    for k in keys:
        prefix = int(bitPrefix(k["d"], 3), 2)
        if prefix < len(prefix_probs):
            mock_oracles[prefix].append(FullOracleDecrypt(k['d'], k['n']))
    #times = [0, 0, 0, 0]
    times = [0,0]
    reps = 10
    cts = [uva_rsa.rsa_enc(pub_e, pub_n, random.randint(0xabc1, 0xabc1234)) for _ in range(reps)]
    start = time.perf_counter_ns()
    for i in range(len(cts)):
        oracle.run(cts[i])
    end = time.perf_counter_ns()
    real_time = ((end - start) / len(cts))
    cts = [uva_rsa.rsa_enc(pub_e, pub_n, random.randint(0xabc1, 0xabc1234)) for _ in range(reps)]
    for k in range(len(prefix_probs)):
        start = time.perf_counter_ns()
        # for i in range(len(mock_oracles[k])):
        for i in range(reps):
            mock_oracles[k][i%len(mock_oracles[k])].run(cts[i%len(cts)])
        end = time.perf_counter_ns()
        times[k] = abs(real_time - ((end - start) / reps))
        # times[k] = abs(((end - start) / reps))
    min_time = min(times)
    min_indexes = [ind for ind, ele in enumerate(times) if ele == min_time]
    result = random.choice(min_indexes)
    return result