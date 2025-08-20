v3 = "yj)jUj?j?j+jUj?j?jjj"
v0 = 0
for i in range(0, len(v3)):
    tmp = (35 * (106 - ord(v3[i])) % 127 + 127) % 127
    print(chr(tmp), end='')

