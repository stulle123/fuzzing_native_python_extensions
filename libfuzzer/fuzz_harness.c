#include <Python.h>
#include <fuzzer/FuzzedDataProvider.h>

#pragma clang optimize off

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    Py_Initialize();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);
    std::string string_data = provider.ConsumeBytesAsString(size);
    char *cstr = new char [string_data.length()+1];
    std::strcpy (cstr, string_data.c_str());

    PyObject* name = PyUnicode_DecodeFSDefault("memory");
    PyObject* module = PyImport_Import(name);
    Py_DECREF(name);

    if (module != NULL) {
        PyObject* corruption_func = PyObject_GetAttrString(module, "corruption");
        PyObject* arg = PyBytes_FromStringAndSize(cstr, size);

        if (arg != NULL) {
            PyObject* res = PyObject_CallFunctionObjArgs(corruption_func, arg, NULL);
            Py_XDECREF(res);
        }

        Py_DECREF(arg);
        Py_DECREF(corruption_func);
        Py_DECREF(module);
    } else {
        PyErr_Print();
        exit(1);
    }

    // https://bugs.python.org/issue1635741
    // Py_Finalize();
    delete[] cstr;
    return 0;
}
