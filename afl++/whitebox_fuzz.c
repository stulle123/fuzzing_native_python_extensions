#include <Python.h>

__AFL_FUZZ_INIT();

#pragma clang optimize off

int main(int argc, char **argv) {
    ssize_t size;
    unsigned char *buf;

    Py_Initialize();
    PyObject* name = PyUnicode_DecodeFSDefault("memory");
    PyObject* module = PyImport_Import(name);
    Py_DECREF(name);

    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif

    buf = __AFL_FUZZ_TESTCASE_BUF;

    if (module != NULL) {
        PyObject* corruption_func = PyObject_GetAttrString(module, "corruption");

        while (__AFL_LOOP(UINT_MAX)) {
            size = __AFL_FUZZ_TESTCASE_LEN;
            PyObject* arg = PyBytes_FromStringAndSize((char *)buf, size);

            if (arg != NULL) {
                PyObject* res = PyObject_CallFunctionObjArgs(corruption_func, arg, NULL);

                if (res != NULL) {
                    Py_XDECREF(res);
                }

                Py_DECREF(arg);
            }
        }

        Py_DECREF(corruption_func);
    }

    Py_DECREF(module);
    return 0;
}
