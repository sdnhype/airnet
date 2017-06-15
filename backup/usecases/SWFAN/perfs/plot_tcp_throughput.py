import matplotlib.pyplot as plt
import numpy as np

# numpy.arange([start, ]stop, [step, ]dtype=None) returns
# evenly spaced values within a given interval.
x = np.arange(start=1, stop=21, step=1)

# Gbps
# First test 16 nov 2015
#bw_c1 = [3.52, 3.61, 3.63, 3.66, 3.64, 3.65, 3.63, 3.62, 3.65, 3.64, 3.65, 3.56, 3.60, 3.66, 3.62, 3.63, 3.67, 3.64, 3.61, 3.63]
#bw_c3 = [3.45, 3.56, 3.58, 3.57, 3.61, 3.55, 3.54, 3.45, 3.56, 3.55, 3.59, 3.50, 3.56, 3.54, 3.58, 3.93, 3.87, 3.82, 3.96, 3.91]
# Second test 16 nov 2015
bw_c1 = [21.4, 20.8, 20.9, 20.7, 20.8, 20.9, 20.9, 20.7, 20.9, 20.7, 21.0, 20.9, 20.7, 14.4, 19.8, 20.4, 17.7, 14.7, 13.7, 19.1]
bw_c3 = [19.4, 21.3, 21.2, 21.1, 21.4, 21.4, 21.1, 21.1, 21.3, 21.0, 20.9, 21.2, 21.4, 21.5, 21.3, 20.9, 21.0, 21.3, 20.9, 21.4]

# Mbps
bw_c2 = [5.25, 5.83, 5.85, 6.22, 5.78, 5.79, 5.40, 5.96, 5.61, 5.86, 5.48, 5.60, 6.42, 6.13, 5.52, 5.89, 6.00, 6.01, 5.69, 5.97]


# red dashes r-- 
# blue squares bs
# green triangles g^
# x  cross 

# plt.plot(x, bw_c1, linestyle='--', marker='o', color='b', label='No network function')
# plt.plot(x, bw_c3, linestyle='--', marker='s', color='r', label='Dynamic control function')
# plt.plot(x, bw_c2, linestyle='--', marker='^', color='g', label='Data function')


plt.figure(1)

plt.subplot(211)
plt.plot(x, bw_c1, linestyle='--', marker='o', color='b', label='No network function')
plt.plot(x, bw_c2, linestyle='--', marker='^', color='r', label='Dynamic control function')
plt.plot(x, bw_c3, linestyle='--', marker='s', color='g', label='Data function')
plt.title("TCP Throughput")
plt.ylabel("Throughput (Gbps)")
plt.grid(True, which='both')
plt.legend(loc='best', shadow=True)
plt.margins(0.05)

"""
plt.subplot(212)
plt.plot(x, bw_c2, linestyle='--', marker='^', color='g', label='Data function')
plt.ylabel("Throughput (Mbps)")
plt.grid(True, which='both')
plt.xlabel("Time (Seconds)")
plt.legend(loc='best', shadow=True)
plt.margins(0.05)
"""
# plt.xticks(x, x)

# plt.yscale("log")
# plt.semilogy(2)
# plt.yscale('symlog', linthreshy=1)
# Since the values close to zero tend toward infinity, there is a need
# to have a range around zero that is linear. The parameter linthresh
# allows the user to specify the size of this range (-linthresh, linthresh).

plt.show()

