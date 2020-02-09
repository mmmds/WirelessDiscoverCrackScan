import itertools

with open("8.txt", "w") as f:
    counter = 0
    for c in itertools.product("0123456789", repeat=8):
        counter += 1
        if counter % 1000 == 0:
            print(str(counter))
        f.write("".join(c) + "\n")
