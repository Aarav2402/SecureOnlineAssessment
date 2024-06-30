import numpy as np
from scipy.stats import f_oneway

small_encryption_times = [0.001350, 0.000383, 0.000238]
medium_encryption_times = [0.000223, 0.000558, 0.000363]
large_encryption_times = [0.001967, 0.000421, 0.000797]

small_decryption_times = [0.014006, 0.007573, 0.004291]
medium_decryption_times = [0.011090, 0.007126, 0.007493]
large_decryption_times = [0.013000, 0.006957, 0.006449]

encryption_f_value, encryption_p_value = f_oneway(small_encryption_times, medium_encryption_times, large_encryption_times)

decryption_f_value, decryption_p_value = f_oneway(small_decryption_times, medium_decryption_times, large_decryption_times)

print("ANOVA Test for Encryption Times")
print(f"F-Value: {encryption_f_value}")
print(f"P-Value: {encryption_p_value}")
if encryption_p_value < 0.05:
    print("The encryption time significantly depends on the size of the data.")
else:
    print("The encryption time does not significantly depend on the size of the data.")

print("\nANOVA Test for Decryption Times")
print(f"F-Value: {decryption_f_value}")
print(f"P-Value: {decryption_p_value}")
if decryption_p_value < 0.05:
    print("The decryption time significantly depends on the size of the data.")
else:
    print("The decryption time does not significantly depend on the size of the data.")
