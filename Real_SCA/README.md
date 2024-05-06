# Attack_scripts

This directory contains attack traces and scripts to carry out the attack for Kyber. There are three trace sets. Two trace sets contain pre-processing traces corresponding to the decrypted message (for Kyber). Each trace set has about 50 traces each. The third trace set has the traces to perform key recovery. The attack script for each scheme is present in the (.m) MATLAB file. The correct secret key used during the attack is stored in a `.dat` file in the respective directories. The MATLAB file uses the correct secret key to deduce the success rate of the attack.

## PC oracle-based Attack:

t-test is first employed between the two trace sets of the pre-processing phase to choose the points of interest (PoI) on the trace distinguishing the two classes (m = 0 or 1). The following technique is used to classify using the identified Points of Interest (PoI).

- `t-test based reduced template technique`: In this technique, we use the PoI to build template for each class and compute their means as reduced templates. In the attack phase, we perform the least sum-of-squared difference test to determine the class.
