import sys
from fortify_compare import FortifyCompare

if __name__ == "__main__":
    print('Number of arguments:', len(sys.argv), 'arguments.')
    print('Argument List:', str(sys.argv))

    if len(sys.argv) < 2:
        print("Usage: fortify_compare.py [Previous FPR File Name] [Current FPR File Name]")

    # just some default file names
    PREVIOUS_FPR = 'MyPreviousScan.fpr'
    CURRENT_FPR = 'MyCurrentScan.fpr'

    if len(sys.argv) > 1:
        PREVIOUS_FPR = sys.argv[1]

    if len(sys.argv) > 2:
        CURRENT_FPR = sys.argv[2]

    COMPARER = FortifyCompare(PREVIOUS_FPR, CURRENT_FPR)
    COMPARER.execute()
