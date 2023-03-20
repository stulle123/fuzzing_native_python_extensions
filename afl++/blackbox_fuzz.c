#include <Python.h>

#pragma clang optimize off

int main(int argc, char **argv) {
    unsigned char buf[1024000];
    ssize_t size;

    Py_Initialize();
    // PyRun_SimpleString("import sys");
    // PyRun_SimpleString("sys.path.append('./')");
    PyObject* name = PyUnicode_DecodeFSDefault("memory");
    PyObject* module = PyImport_Import(name);
    Py_DECREF(name);

    if (module != NULL) {
        PyObject* corruption_func = PyObject_GetAttrString(module, "corruption");

        while ((size = read(0, buf, sizeof(buf))) > 0 ? 1 : 0) {
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
        Py_DECREF(module);
    }

    return 0;
}
